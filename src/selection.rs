//! Deterministic selection-bitmap derivation for a `(source_id, registry_version, timestamp)` round.

use solana_keccak_hasher::hashv;

use crate::bitmap::{
    Bitmap, derive_group_bitmap,
    effective_selection_size,
};
use crate::error::AttestationError;
use crate::RegistryView;

/// `keccak256("MOLPHA_SELECTION_V1")` domain separator.
pub const SELECTION_SEED_PREFIX: [u8; 32] = [
    0x1d, 0xef, 0x81, 0x59, 0xcb, 0xcf, 0xcd, 0xfd, 0x72, 0x8d, 0x41, 0x97, 0x51, 0x9a, 0x57, 0xc0,
    0x6e, 0x24, 0x3f, 0x0d, 0x94, 0x68, 0xb4, 0xc1, 0xe5, 0xc4, 0xa2, 0x33, 0xfc, 0x56, 0x53, 0xc3,
];

/// Derive the selection bitmap for a round.
///
/// `seed = keccak(SELECTION_SEED_PREFIX, source_id, registry_version_be, canonical_timestamp_be)`,
/// then [`derive_group_bitmap`](crate::bitmap::derive_group_bitmap) with
/// [`effective_selection_size`](crate::bitmap::effective_selection_size).
pub fn derive_selection_bitmap(
    source_id: &[u8; 32],
    canonical_timestamp: u64,
    signatures_required: u8,
    registry: &RegistryView,
) -> Result<Bitmap, AttestationError> {
    let registry_version_bytes = registry.version.to_be_bytes();
    let canonical_timestamp_bytes = canonical_timestamp.to_be_bytes();
    let selection_seed = hashv(&[
        SELECTION_SEED_PREFIX.as_slice(),
        source_id.as_ref(),
        registry_version_bytes.as_ref(),
        canonical_timestamp_bytes.as_ref(),
    ])
    .to_bytes();
    let selection_size =
        effective_selection_size(signatures_required, registry.redundancy_buffer as u8, registry.node_count as u32);
    derive_group_bitmap(&selection_seed, registry.node_count as u32, selection_size)
}

/// Selection / threshold checks shared by attestation verification.
///
/// Returns `Ok(true)` when `signers ⊆ expected_selection` and counts match; `Ok(false)` when the
/// bitmap is a strict superset of the allowed selection. Structural problems surface as `Err`.
pub fn verify_selection(
    source_id: &[u8; 32],
    canonical_timestamp: u64,
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

    let expected_selection_bitmap = derive_selection_bitmap(source_id, canonical_timestamp, signatures_required, registry)?;
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
}
