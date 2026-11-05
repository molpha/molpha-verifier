//! Deterministic selection-bitmap derivation for a `(source_id, registry_version, timestamp window)` round.

use solana_keccak_hasher::hashv;

use crate::bitmap::{derive_group_bitmap, effective_selection_size, for_each_set_bit, Bitmap};
use crate::error::AttestationError;
use crate::state::NODE_SLOTS;
use crate::RegistryView;

/// `keccak256("MOLPHA_SELECTION_V1")` domain separator.
pub const SELECTION_SEED_PREFIX: [u8; 32] = [
    0x1d, 0xef, 0x81, 0x59, 0xcb, 0xcf, 0xcd, 0xfd, 0x72, 0x8d, 0x41, 0x97, 0x51, 0x9a, 0x57, 0xc0,
    0x6e, 0x24, 0x3f, 0x0d, 0x94, 0x68, 0xb4, 0xc1, 0xe5, 0xc4, 0xa2, 0x33, 0xfc, 0x56, 0x53, 0xc3,
];

/// Width in milliseconds of the window that feeds committee selection. Selection reads
/// `timestamp / SELECTION_WINDOW_MS`, so timestamp precision finer than a window never
/// changes who is selected. Changing this value is a consensus break: bump the prefix with it.
pub const SELECTION_WINDOW_MS: u64 = 1_000;

/// Derive the selection bitmap for a round.
///
/// `timestamp` is unix milliseconds. With `window = timestamp /
/// SELECTION_WINDOW_MS`,
/// `seed = keccak(SELECTION_SEED_PREFIX, source_id, registry_version_be, window_be)`,
/// then [`derive_group_bitmap`] with [`effective_selection_size`].
///
/// The draw runs over the live **node** members: `n` is [`RegistryView::live_count`], not the
/// record count, and the `r`-th selected rank maps to the slot of the `r`-th live node. Without
/// holes the ranks are the slots, so the result is the plain sampler output. Provider records
/// (index `NODE_SLOTS` and up) are never drawn and never change the draw. The registry's member
/// table must be present for a snapshot that has holes.
///
/// Selection is for load balancing, slashing and activity tracking. [`crate::verify`] does not
/// use it.
pub fn derive_selection_bitmap(
    source_id: &[u8; 32],
    timestamp: u64,
    signatures_required: u8,
    registry: &RegistryView,
) -> Result<Bitmap, AttestationError> {
    let registry_version_bytes = registry.version.to_be_bytes();
    let selection_window_bytes = (timestamp / SELECTION_WINDOW_MS).to_be_bytes();
    let selection_seed = hashv(&[
        SELECTION_SEED_PREFIX.as_slice(),
        source_id.as_ref(),
        registry_version_bytes.as_ref(),
        selection_window_bytes.as_ref(),
    ])
    .to_bytes();
    let live = registry.live_slots();
    let live_count = live.len() as u32;
    let selection_size =
        effective_selection_size(signatures_required, registry.redundancy_buffer, live_count);
    let ranks = derive_group_bitmap(&selection_seed, live_count, selection_size)?;
    // No node hole below the last node slot: the ranks are the slots. Node slots past `NODE_SLOTS`
    // are providers, so they do not count toward the dense prefix.
    if live_count == u32::from(registry.node_count).min(NODE_SLOTS as u32) {
        return Ok(ranks);
    }
    let mut slots = Bitmap::EMPTY;
    for_each_set_bit(ranks, |rank| {
        let slot = live
            .slot(rank)
            .ok_or(AttestationError::GroupBitmapDerivationFailed)?;
        slots.set_bit(slot);
        Ok(())
    })?;
    Ok(slots)
}

/// The quorum rule `verify` enforces: a non-empty bitmap with at least one signer, at most one
/// provider bit, and `popcount(signers) >= signatures_required`.
///
/// A provider signer counts like a node: a provider round is `signatures_required - 1` nodes plus
/// the provider. More than one provider bit is refused (`InvalidSignersBitmap`), so providers can
/// never make up more than one signer of a quorum. `signatures_required == 0` never passes.
#[inline(always)]
pub fn check_quorum(signers: &Bitmap, signatures_required: u8) -> Result<(), AttestationError> {
    if *signers == Bitmap::EMPTY {
        return Err(AttestationError::InvalidSignersBitmap);
    }
    if signatures_required == 0 {
        return Err(AttestationError::InsufficientSigners);
    }
    if signers.provider_bits().popcount() > 1 {
        return Err(AttestationError::InvalidSignersBitmap);
    }
    if signers.popcount() < u32::from(signatures_required) {
        return Err(AttestationError::InsufficientSigners);
    }
    Ok(())
}

/// How many **nodes** an attestation's committee holds: `signatures_required`, less one when the
/// signers carry a provider bit (the provider is the last signer of the quorum).
///
/// Selection, dispatch, tickets and slashing size the committee by this number, not by the wire
/// `signatures_required`. The draw is not nested across sizes, so using the wrong one can flag an
/// honest signer as unsolicited.
#[inline]
pub fn node_quorum(signatures_required: u8, signers: &Bitmap) -> u8 {
    if signers.provider_bits() == Bitmap::EMPTY {
        signatures_required
    } else {
        signatures_required.saturating_sub(1)
    }
}

/// [`derive_selection_bitmap`] for an attestation: the committee of `node_quorum(t, signers)`
/// nodes, whichever kind of round produced `signers`.
pub fn attestation_selection(
    source_id: &[u8; 32],
    timestamp: u64,
    signatures_required: u8,
    signers: &Bitmap,
    registry: &RegistryView,
) -> Result<Bitmap, AttestationError> {
    derive_selection_bitmap(
        source_id,
        timestamp,
        node_quorum(signatures_required, signers),
        registry,
    )
}

/// Selection / threshold checks for callers that police the committee: slashing evidence and
/// activity tracking. [`crate::verify`] does not call this.
///
/// Returns `Ok(true)` when the node signers `⊆ expected_selection` and counts match; `Ok(false)`
/// when they are a strict superset of the allowed selection. The selection is the committee of
/// [`node_quorum`] nodes; provider bits are not nodes and are ignored by the subset check.
/// Structural problems surface as `Err`.
pub fn verify_selection(
    source_id: &[u8; 32],
    timestamp: u64,
    signatures_required: u8,
    registry: &RegistryView,
    signers_bitmap: &[u8; 32],
) -> Result<bool, AttestationError> {
    let signers = Bitmap::load(signers_bitmap);
    check_quorum(&signers, signatures_required)?;

    let expected_selection_bitmap = attestation_selection(
        source_id,
        timestamp,
        signatures_required,
        &signers,
        registry,
    )?;
    Ok(signers.node_bits().is_subset(&expected_selection_bitmap))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selection_seed_prefix_is_keccak_of_domain() {
        let expected = hashv(&[b"MOLPHA_SELECTION_V1"]).to_bytes();
        assert_eq!(SELECTION_SEED_PREFIX, expected);
    }

    fn registry(version: u32, node_count: u16) -> RegistryView<'static> {
        RegistryView {
            version,
            node_count,
            provider_count: 0,
            redundancy_buffer: 2,
            nodes: &[],
            providers: &[],
        }
    }

    #[test]
    fn timestamps_in_one_window_select_the_same_committee() {
        let source = [7u8; 32];
        let registry = registry(3, 12);
        let base = 1_705_257_421u64 * SELECTION_WINDOW_MS;
        let first = derive_selection_bitmap(&source, base, 5, &registry).unwrap();
        for offset in [1, 250, 500, SELECTION_WINDOW_MS - 1] {
            let got = derive_selection_bitmap(&source, base + offset, 5, &registry).unwrap();
            assert_eq!(got.to_bytes(), first.to_bytes(), "offset {offset} ms");
        }
    }

    #[test]
    fn the_window_boundary_changes_the_seed() {
        // 999 ms and 1000 ms straddle a window edge; adjacent windows must not share a seed, so
        // sweep several to avoid asserting on one coincidentally equal 12-node subset.
        let source = [9u8; 32];
        let registry = registry(3, 64);
        let mut differing = 0;
        for w in 0..16u64 {
            let edge = (1_000_000 + w) * SELECTION_WINDOW_MS;
            let before = derive_selection_bitmap(&source, edge - 1, 5, &registry).unwrap();
            let after = derive_selection_bitmap(&source, edge, 5, &registry).unwrap();
            if before.to_bytes() != after.to_bytes() {
                differing += 1;
            }
        }
        assert!(
            differing >= 14,
            "only {differing}/16 window edges changed the committee"
        );
    }

    fn members(live: &[bool]) -> Vec<crate::NodeEntry> {
        live.iter()
            .enumerate()
            .map(|(i, live)| crate::NodeEntry {
                account: if *live { [i as u8 + 1; 32] } else { [0; 32] },
                ..crate::NodeEntry::default()
            })
            .collect()
    }

    fn view<'a>(version: u32, nodes: &'a [crate::NodeEntry], buffer: u8) -> RegistryView<'a> {
        RegistryView {
            version,
            node_count: nodes.len() as u16,
            provider_count: 0,
            redundancy_buffer: buffer,
            nodes,
            providers: &[],
        }
    }

    #[test]
    fn a_registry_without_holes_selects_as_before() {
        let source = [3u8; 32];
        let nodes = members(&[true; 12]);
        let dense = derive_selection_bitmap(&source, 1_705_257_421_000, 5, &view(3, &nodes, 2));
        let bare = derive_selection_bitmap(&source, 1_705_257_421_000, 5, &registry_with(3, 12));
        assert_eq!(dense.unwrap().to_bytes(), bare.unwrap().to_bytes());
    }

    fn registry_with(version: u32, node_count: u16) -> RegistryView<'static> {
        RegistryView {
            version,
            node_count,
            provider_count: 0,
            redundancy_buffer: 2,
            nodes: &[],
            providers: &[],
        }
    }

    #[test]
    fn holes_are_never_selected_and_the_committee_keeps_its_size() {
        let mut live = vec![true; 20];
        for hole in [0, 4, 5, 13] {
            live[hole] = false;
        }
        let nodes = members(&live);
        for w in 0..64u64 {
            let selection = derive_selection_bitmap(
                &[w as u8; 32],
                w * SELECTION_WINDOW_MS,
                5,
                &view(9, &nodes, 2),
            )
            .unwrap();
            assert_eq!(selection.popcount(), 7, "window {w}");
            for hole in [0usize, 4, 5, 13] {
                assert!(!selection.bit_set(hole), "window {w} selected hole {hole}");
            }
        }
    }

    #[test]
    fn the_committee_is_the_dense_draw_mapped_through_the_live_slots() {
        let live = [
            true, false, true, true, false, true, true, true, false, true, true, true,
        ];
        let nodes = members(&live);
        let registry = view(5, &nodes, 2);
        let live_slots: Vec<usize> = (0..live.len()).filter(|i| live[*i]).collect();
        for w in 0..32u64 {
            let source = [w as u8; 32];
            let timestamp = (1_700_000_000 + w) * SELECTION_WINDOW_MS;
            let got = derive_selection_bitmap(&source, timestamp, 3, &registry).unwrap();
            // A registry of just the live members, in the same order, draws the same ranks.
            let packed = members(&vec![true; live_slots.len()]);
            let ranks =
                derive_selection_bitmap(&source, timestamp, 3, &view(5, &packed, 2)).unwrap();
            let mut expected = Bitmap::EMPTY;
            for (rank, slot) in live_slots.iter().enumerate() {
                if ranks.bit_set(rank) {
                    expected.set_bit(*slot);
                }
            }
            assert_eq!(got.to_bytes(), expected.to_bytes(), "window {w}");
        }
    }

    /// A provider table with live records at the given provider slots and holes elsewhere.
    fn providers(provider_slots: &[usize]) -> Vec<crate::NodeEntry> {
        let mut table = Vec::new();
        for slot in provider_slots {
            if table.len() <= *slot {
                table.resize(slot + 1, crate::NodeEntry::default());
            }
            table[*slot].account = [0xA0 + *slot as u8; 32];
        }
        table
    }

    /// [`view`] with a provider table beside the nodes.
    fn with_providers<'a>(
        version: u32,
        nodes: &'a [crate::NodeEntry],
        providers: &'a [crate::NodeEntry],
        buffer: u8,
    ) -> RegistryView<'a> {
        RegistryView {
            provider_count: providers.len() as u16,
            providers,
            ..view(version, nodes, buffer)
        }
    }

    #[test]
    fn provider_records_never_change_the_committee() {
        // Dense nodes (the fast path), then nodes with holes (the mapped path).
        let dense = [true; 20];
        let mut holey = [true; 20];
        for hole in [0, 4, 5, 13] {
            holey[hole] = false;
        }
        let full = [true; NODE_SLOTS];
        let table = providers(&[1, 2, 40]);
        for live in [&dense[..], &holey[..], &full[..]] {
            let nodes = members(live);
            for w in 0..32u64 {
                let source = [w as u8; 32];
                let timestamp = (1_700_000_000 + w) * SELECTION_WINDOW_MS;
                let without = derive_selection_bitmap(&source, timestamp, 5, &view(7, &nodes, 2));
                let got = derive_selection_bitmap(
                    &source,
                    timestamp,
                    5,
                    &with_providers(7, &nodes, &table, 2),
                );
                assert_eq!(got.unwrap().to_bytes(), without.unwrap().to_bytes());
            }
        }
    }

    #[test]
    fn no_node_hole_below_the_providers_takes_the_dense_draw() {
        // 64 live nodes and a provider: the ranks are still the slots.
        let dense = members(&[true; NODE_SLOTS]);
        let table = providers(&[1]);
        let got = derive_selection_bitmap(
            &[2; 32],
            1_700_000_000_000,
            5,
            &with_providers(1, &dense, &table, 2),
        );
        let want = derive_selection_bitmap(&[2; 32], 1_700_000_000_000, 5, &view(1, &dense, 2));
        assert_eq!(got.unwrap().to_bytes(), want.unwrap().to_bytes());
        assert_eq!(want.unwrap().popcount(), 7);
    }

    #[test]
    fn a_selection_never_reaches_the_provider_bits() {
        let nodes = members(&[true; 30]);
        let table = providers(&[1, 2]);
        for w in 0..64u64 {
            let got = derive_selection_bitmap(
                &[w as u8; 32],
                w * 1_000,
                5,
                &with_providers(1, &nodes, &table, 2),
            );
            assert_eq!(got.unwrap().node_bits(), got.unwrap());
        }
        // Even a selection-only caller that claims more node slots than the segment has draws
        // over the first 64.
        let claimed = RegistryView {
            version: 1,
            node_count: 200,
            provider_count: 0,
            redundancy_buffer: 2,
            nodes: &[],
            providers: &[],
        };
        let got = derive_selection_bitmap(&[9; 32], 5_000, 5, &claimed).unwrap();
        assert_eq!(got.node_bits(), got);
        let capped = registry(1, NODE_SLOTS as u16);
        assert_eq!(
            got.to_bytes(),
            derive_selection_bitmap(&[9; 32], 5_000, 5, &capped)
                .unwrap()
                .to_bytes()
        );
    }

    fn bitmap(bits: &[usize]) -> Bitmap {
        let mut bitmap = Bitmap::EMPTY;
        for bit in bits {
            bitmap.set_bit(*bit);
        }
        bitmap
    }

    #[test]
    fn the_quorum_counts_every_signer() {
        // Five nodes meet a threshold of five.
        assert_eq!(check_quorum(&bitmap(&[0, 1, 2, 3, 4]), 5), Ok(()));
        // A provider counts like a node: four nodes plus the provider meet five.
        assert_eq!(check_quorum(&bitmap(&[0, 1, 2, 3, 64]), 5), Ok(()));
        assert_eq!(check_quorum(&bitmap(&[0, 1, 2, 3, 255]), 5), Ok(()));
        // Three nodes plus the provider are one short of five.
        assert_eq!(
            check_quorum(&bitmap(&[0, 1, 2, 64]), 5),
            Err(AttestationError::InsufficientSigners)
        );
        // Bits 63 and 64 are on either side of the split, and both count.
        assert_eq!(check_quorum(&bitmap(&[63]), 1), Ok(()));
        assert_eq!(check_quorum(&bitmap(&[64]), 1), Ok(()));
        assert_eq!(
            check_quorum(&bitmap(&[64]), 2),
            Err(AttestationError::InsufficientSigners)
        );
    }

    #[test]
    fn a_second_provider_bit_is_refused_however_high_the_threshold_is() {
        for bits in [&[0, 1, 2, 3, 64, 65][..], &[0, 1, 64, 255], &[64, 65, 66]] {
            for required in [1u8, 2, 3, 6] {
                assert_eq!(
                    check_quorum(&bitmap(bits), required),
                    Err(AttestationError::InvalidSignersBitmap),
                    "{bits:?} at {required}"
                );
            }
        }
    }

    #[test]
    fn an_empty_bitmap_or_a_zero_threshold_never_passes() {
        for required in [0u8, 1] {
            assert_eq!(
                check_quorum(&Bitmap::EMPTY, required),
                Err(AttestationError::InvalidSignersBitmap)
            );
        }
        for bits in [&[0][..], &[0, 1, 2], &[64], &[0, 64]] {
            assert_eq!(
                check_quorum(&bitmap(bits), 0),
                Err(AttestationError::InsufficientSigners),
                "{bits:?}"
            );
        }
    }

    #[test]
    fn the_node_quorum_is_one_less_when_the_provider_signed() {
        assert_eq!(node_quorum(5, &bitmap(&[0, 1, 2, 3, 4])), 5);
        assert_eq!(node_quorum(5, &bitmap(&[0, 1, 2, 3, 64])), 4);
        assert_eq!(node_quorum(5, &bitmap(&[0, 1, 2, 3, 255])), 4);
        assert_eq!(node_quorum(1, &bitmap(&[64])), 0);
        assert_eq!(node_quorum(0, &bitmap(&[64])), 0);
    }

    #[test]
    fn a_provider_round_is_selected_by_its_node_quorum() {
        let nodes = members(&[true; 12]);
        let registry = view(3, &nodes, 2);
        let source = [7u8; 32];
        let committee = bitmap(&[0, 1, 2, 3, 4]);
        let provider_round = bitmap(&[0, 1, 2, 3, 64]);
        for window in 0..64u64 {
            let ts = 1_705_257_000_000 + window * 1_000;
            // The same draw as an ordinary round of the node quorum, and the committee round
            // keeps the wire threshold.
            assert_eq!(
                attestation_selection(&source, ts, 5, &committee, &registry),
                derive_selection_bitmap(&source, ts, 5, &registry)
            );
            assert_eq!(
                attestation_selection(&source, ts, 5, &provider_round, &registry),
                derive_selection_bitmap(&source, ts, 4, &registry)
            );
        }
    }

    /// The draw is not nested across sizes: the complement sampler takes over above half, so a
    /// node can sit in the t - 1 draw and not in the t draw. A provider round must therefore be
    /// judged by the node quorum, or an honest signer reads as unsolicited.
    #[test]
    fn the_draw_of_one_less_is_not_always_inside_the_draw() {
        let nodes = members(&[true; 4]);
        let registry = view(1, &nodes, 0);
        let mut found = 0;
        for window in 0..256u64 {
            let ts = window * 1_000;
            let full = derive_selection_bitmap(&[3; 32], ts, 3, &registry).unwrap();
            let smaller = derive_selection_bitmap(&[3; 32], ts, 2, &registry).unwrap();
            if smaller.is_subset(&full) {
                continue;
            }
            found += 1;
            // The provider round's two nodes come from the smaller draw: selected by the node
            // quorum, although the wire threshold's draw would not contain them.
            let mut signers = smaller;
            signers.set_bit(NODE_SLOTS);
            assert_eq!(
                verify_selection(&[3; 32], ts, 3, &registry, &signers.to_bytes()),
                Ok(true)
            );
            // The same two nodes without the provider bit are a committee round of three: not
            // enough signers.
            assert_eq!(
                verify_selection(&[3; 32], ts, 3, &registry, &smaller.to_bytes()),
                Err(AttestationError::InsufficientSigners)
            );
        }
        assert!(
            found > 0,
            "no window where the smaller draw leaves the larger one"
        );
    }

    #[test]
    fn verify_selection_draws_a_provider_round_by_its_node_quorum() {
        let nodes = members(&[true; 12]);
        let table = providers(&[1]);
        let registry = with_providers(3, &nodes, &table, 2);
        let ts = 1_705_257_421_000;
        // t = 5 with the provider: four nodes, so the committee is 4 + 2 buffer.
        let selection = derive_selection_bitmap(&[7; 32], ts, 4, &registry).unwrap();
        assert_eq!(selection.popcount(), 6);

        let mut signers = selection.node_bits();
        signers.set_bit(NODE_SLOTS + 1);
        assert_eq!(
            verify_selection(&[7; 32], ts, 5, &registry, &signers.to_bytes()),
            Ok(true)
        );
        // An unselected node still fails it.
        let outside = (0..12).find(|bit| !selection.bit_set(*bit)).unwrap();
        signers.set_bit(outside);
        assert_eq!(
            verify_selection(&[7; 32], ts, 5, &registry, &signers.to_bytes()),
            Ok(false)
        );
        // Without a provider bit the same threshold selects five nodes plus the buffer.
        let committee = derive_selection_bitmap(&[7; 32], ts, 5, &registry).unwrap();
        assert_eq!(committee.popcount(), 7);
        assert_eq!(
            verify_selection(&[7; 32], ts, 5, &registry, &committee.to_bytes()),
            Ok(true)
        );
    }

    #[test]
    fn a_registry_with_no_live_member_selects_nothing() {
        let nodes = members(&[false; 4]);
        assert!(derive_selection_bitmap(&[1; 32], 0, 1, &view(1, &nodes, 1)).is_err());
    }
}
