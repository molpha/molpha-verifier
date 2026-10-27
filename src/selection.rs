//! Deterministic selection-bitmap derivation for a `(source_id, registry_version, timestamp window)` round.

use solana_keccak_hasher::hashv;

use crate::bitmap::{derive_group_bitmap, effective_selection_size, for_each_set_bit, Bitmap};
use crate::error::AttestationError;
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
/// The draw runs over the **live** members: `n` is [`RegistryView::live_count`], not the slot
/// count, and the `r`-th selected rank maps to the slot of the `r`-th live member. Without holes
/// the ranks are the slots, so the result is the plain sampler output. The registry's member table
/// must be present for a snapshot that has holes.
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
    if live_count == u32::from(registry.node_count) {
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

/// The quorum rule `verify` enforces: a non-empty signer set of at least `signatures_required`.
#[inline(always)]
pub fn check_quorum(signers: &Bitmap, signatures_required: u8) -> Result<(), AttestationError> {
    let signer_count = signers.popcount();
    if signer_count == 0 {
        return Err(AttestationError::InvalidSignersBitmap);
    }
    if signer_count < u32::from(signatures_required) {
        return Err(AttestationError::InsufficientSigners);
    }
    Ok(())
}

/// Selection / threshold checks for callers that police the committee: slashing evidence and
/// activity tracking. [`crate::verify`] does not call this.
///
/// Returns `Ok(true)` when `signers ⊆ expected_selection` and counts match; `Ok(false)` when the
/// bitmap is a strict superset of the allowed selection. Structural problems surface as `Err`.
pub fn verify_selection(
    source_id: &[u8; 32],
    timestamp: u64,
    signatures_required: u8,
    registry: &RegistryView,
    signers_bitmap: &[u8; 32],
) -> Result<bool, AttestationError> {
    let signers = Bitmap::load(signers_bitmap);
    check_quorum(&signers, signatures_required)?;

    let expected_selection_bitmap =
        derive_selection_bitmap(source_id, timestamp, signatures_required, registry)?;
    Ok(signers.is_subset(&expected_selection_bitmap))
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
            redundancy_buffer: 2,
            nodes: &[],
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
            redundancy_buffer: buffer,
            nodes,
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
            redundancy_buffer: 2,
            nodes: &[],
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

    #[test]
    fn a_registry_with_no_live_member_selects_nothing() {
        let nodes = members(&[false; 4]);
        assert!(derive_selection_bitmap(&[1; 32], 0, 1, &view(1, &nodes, 1)).is_err());
    }
}
