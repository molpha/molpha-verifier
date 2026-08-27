//! Deterministic selection-bitmap derivation for a `(source_id, registry_version, timestamp)` round.

use ethnum::U256;
use solana_keccak_hasher::hashv;

use crate::bitmap::{bitmap_store, derive_group_bitmap_u256, effective_selection_size};
use crate::error::AttestationError;

/// `keccak256("MOLPHA_SELECTION_V1")` domain separator.
pub const SELECTION_SEED_PREFIX: [u8; 32] = [
    0x1d, 0xef, 0x81, 0x59, 0xcb, 0xcf, 0xcd, 0xfd, 0x72, 0x8d, 0x41, 0x97, 0x51, 0x9a, 0x57, 0xc0,
    0x6e, 0x24, 0x3f, 0x0d, 0x94, 0x68, 0xb4, 0xc1, 0xe5, 0xc4, 0xa2, 0x33, 0xfc, 0x56, 0x53, 0xc3,
];

/// Derive the selection bitmap for a round.
///
/// `seed = keccak(SELECTION_SEED_PREFIX, source_id, registry_version_be, canonical_timestamp_be)`,
/// then `derive_group_bitmap(seed, node_count, effective_selection_size(...))`.
pub fn derive_selection_bitmap(
    source_id: &[u8; 32],
    registry_version: u32,
    canonical_timestamp: u64,
    node_count: u32,
    signatures_required: u8,
    redundancy_buffer: u8,
) -> Result<[u8; 32], AttestationError> {
    Ok(bitmap_store(derive_selection_bitmap_u256(
        source_id,
        registry_version,
        canonical_timestamp,
        node_count,
        signatures_required,
        redundancy_buffer,
    )?))
}

/// [`derive_selection_bitmap`] returning `U256` (avoids a store/load round-trip).
pub fn derive_selection_bitmap_u256(
    source_id: &[u8; 32],
    registry_version: u32,
    canonical_timestamp: u64,
    node_count: u32,
    signatures_required: u8,
    redundancy_buffer: u8,
) -> Result<U256, AttestationError> {
    let registry_version_bytes = registry_version.to_be_bytes();
    let canonical_timestamp_bytes = canonical_timestamp.to_be_bytes();
    let selection_seed = hashv(&[
        SELECTION_SEED_PREFIX.as_slice(),
        source_id.as_ref(),
        registry_version_bytes.as_ref(),
        canonical_timestamp_bytes.as_ref(),
    ])
    .to_bytes();
    let selection_size =
        effective_selection_size(signatures_required, redundancy_buffer, node_count);
    derive_group_bitmap_u256(&selection_seed, node_count, selection_size)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selection_seed_prefix_is_keccak_of_domain() {
        let expected = hashv(&[b"MOLPHA_SELECTION_V1"]).to_bytes();
        assert_eq!(SELECTION_SEED_PREFIX, expected);
    }
}
