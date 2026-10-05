//! Deterministic selection-bitmap derivation for a `(source_id, registry_version, timestamp window)` round.

use solana_keccak_hasher::hashv;

use crate::bitmap::{derive_group_bitmap, effective_selection_size, Bitmap};
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
    let selection_size = effective_selection_size(
        signatures_required,
        registry.redundancy_buffer,
        registry.node_count as u32,
    );
    derive_group_bitmap(&selection_seed, registry.node_count as u32, selection_size)
}

/// Selection / threshold checks shared by attestation verification.
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
    let signer_count = signers.popcount();
    if signer_count == 0 {
        return Err(AttestationError::InvalidSignersBitmap);
    }
    if signer_count < u32::from(signatures_required) {
        return Err(AttestationError::InsufficientSigners);
    }

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
}
