//! High-level attestation verification over caller-supplied signer pubkeys.
//!
//! These functions are pure: the caller resolves the signer pubkeys (e.g. from an on-chain
//! registry, an off-chain snapshot, or hard-coded constants) and passes them in. No anchor,
//! no `AccountInfo`, no PDA reads.

use solana_secp256k1_recover::secp256k1_recover;

use crate::bitmap::{bitmap_is_subset_u256, bitmap_load};
use crate::coalition::CoalitionAccumulator;
use crate::error::AttestationError;
use crate::message::compute_message_hash;
use crate::payload::{Attestation, AttestationPayload, SchnorrSignature};
use crate::scalar::{
    eth_address_from_uncompressed_pubkey, evm_schnorr_ecdsa_inputs,
    secp256k1_scalar_is_valid_nonzero,
};
use crate::selection::derive_selection_bitmap;

/// Stored secp256k1 affine coordinates `(x, y)`, big-endian — as kept in a `Node`.
pub type SignerXy = ([u8; 32], [u8; 32]);

/// Verify an attestation against caller-supplied signer pubkeys.
///
/// # Caller contract
/// - `node_count` is the registry node count for `attestation.payload.registry_version`.
/// - `ordered_signers` holds one `(x, y)` per set bit of `attestation.signature.signers_bitmap`,
///   in **ascending bit-index order** — the same order EVM `Validator.verify` combines pubkeys.
///   The caller is responsible for resolving the authentic pubkeys; this function trusts the
///   supplied set.
///
/// Re-derives the selection bitmap internally and enforces `signers ⊆ selection`. Checks run in the
/// same order as the on-chain monolith: scalar validity → signer threshold → selection subset →
/// signer-count match → coalition reconstruction → message hash → Schnorr recovery.
pub fn verify_attestation(
    attestation: &Attestation,
    node_count: u32,
    redundancy_buffer: u8,
    ordered_signers: &[SignerXy],
) -> Result<(), AttestationError> {
    verify_attestation_parts(
        &attestation.payload,
        &attestation.signature,
        node_count,
        redundancy_buffer,
        ordered_signers,
    )
}

/// Like [`verify_attestation`] but taking compressed (33-byte) signer pubkeys.
pub fn verify_attestation_compressed(
    attestation: &Attestation,
    node_count: u32,
    redundancy_buffer: u8,
    ordered_signers_compressed: &[[u8; 33]],
) -> Result<(), AttestationError> {
    let xy = decompress_all(ordered_signers_compressed)?;
    verify_attestation_parts(
        &attestation.payload,
        &attestation.signature,
        node_count,
        redundancy_buffer,
        &xy,
    )
}

pub(crate) fn verify_attestation_parts(
    payload: &AttestationPayload,
    signature: &SchnorrSignature,
    node_count: u32,
    redundancy_buffer: u8,
    ordered_signers: &[SignerXy],
) -> Result<(), AttestationError> {
    if signature.agg_sig_s == [0u8; 32] || !secp256k1_scalar_is_valid_nonzero(&signature.agg_sig_s)
    {
        return Err(AttestationError::InvalidAggregateSignature);
    }

    let signers = bitmap_load(&signature.signers_bitmap);
    let signer_count = signers.count_ones();
    if signer_count < payload.signatures_required {
        return Err(AttestationError::InsufficientSigners);
    }

    let expected_selection = derive_selection_bitmap(
        &payload.source_id,
        payload.registry_version,
        payload.canonical_timestamp,
        node_count,
        payload.signatures_required,
        redundancy_buffer,
    )?;
    if !bitmap_is_subset_u256(signers, bitmap_load(&expected_selection)) {
        return Err(AttestationError::SignersNotSubsetOfSelection);
    }

    if ordered_signers.len() != signer_count as usize {
        return Err(AttestationError::SignerCountMismatch);
    }

    let x_coalition = reconstruct_coalition_key(ordered_signers)?;
    let message_hash = compute_message_hash(
        payload,
        signature.signers_bitmap,
        payload.signatures_required,
    );

    if recover_and_match(
        &x_coalition,
        &message_hash,
        &signature.agg_sig_s,
        &signature.commitment_addr,
    ) {
        Ok(())
    } else {
        Err(AttestationError::InvalidAggregateSignature)
    }
}

/// Reconstruct the coalition key `Σ X_i` from ordered signer pubkeys → compressed (33 bytes).
///
/// Errors on an empty signer set or a point-at-infinity sum.
pub fn reconstruct_coalition_key(
    ordered_signers: &[SignerXy],
) -> Result<[u8; 33], AttestationError> {
    if ordered_signers.is_empty() {
        return Err(AttestationError::InvalidSignersBitmap);
    }
    let mut coalition = CoalitionAccumulator::default();
    for (x, y) in ordered_signers {
        coalition.add_stored_xy(x, y)?;
    }
    coalition.compressed_pubkey()
}

/// Compressed-pubkey variant of [`reconstruct_coalition_key`].
pub fn reconstruct_coalition_key_compressed(
    ordered_signers_compressed: &[[u8; 33]],
) -> Result<[u8; 33], AttestationError> {
    let xy = decompress_all(ordered_signers_compressed)?;
    reconstruct_coalition_key(&xy)
}

/// Verify the aggregate Schnorr signature over an arbitrary `message_hash` against the coalition
/// formed by `ordered_signers`.
///
/// Returns `Ok(true)` when valid (no fraud), `Ok(false)` when invalid (fabricated / committed
/// garbage → slashable). `Err` only on malformed input (empty signer set, bad curve point). This
/// mirrors the dispute-path semantics in the Molpha program.
pub fn verify_aggregate_over_hash(
    ordered_signers: &[SignerXy],
    agg_sig_s: &[u8; 32],
    commitment_addr: &[u8; 20],
    message_hash: &[u8; 32],
) -> Result<bool, AttestationError> {
    if !secp256k1_scalar_is_valid_nonzero(agg_sig_s) {
        return Ok(false);
    }
    let x_coalition = reconstruct_coalition_key(ordered_signers)?;
    Ok(recover_and_match(
        &x_coalition,
        message_hash,
        agg_sig_s,
        commitment_addr,
    ))
}

/// Run the Schnorr→ECDSA recovery trick and compare the recovered address to `commitment_addr`.
fn recover_and_match(
    x_coalition: &[u8; 33],
    message_hash: &[u8; 32],
    agg_sig_s: &[u8; 32],
    commitment_addr: &[u8; 20],
) -> bool {
    let (recovery_id, ecdsa_signature, ecdsa_hash) =
        match evm_schnorr_ecdsa_inputs(x_coalition, message_hash, agg_sig_s, commitment_addr) {
            Ok(v) => v,
            Err(_) => return false,
        };
    let recovered = match secp256k1_recover(&ecdsa_hash, recovery_id, &ecdsa_signature) {
        Ok(r) => r,
        Err(_) => return false,
    };
    eth_address_from_uncompressed_pubkey(recovered.to_bytes()) == *commitment_addr
}

fn decompress_all(compressed: &[[u8; 33]]) -> Result<Vec<SignerXy>, AttestationError> {
    use libsecp256k1::{PublicKey, PublicKeyFormat};
    compressed
        .iter()
        .map(|c| {
            let pk = PublicKey::parse_slice(c, Some(PublicKeyFormat::Compressed))
                .map_err(|_| AttestationError::InvalidAggregateSignature)?;
            let full = pk.serialize(); // 0x04 || x || y
            let x: [u8; 32] = full[1..33].try_into().unwrap();
            let y: [u8; 32] = full[33..65].try_into().unwrap();
            Ok((x, y))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::message::MESSAGE_PREFIX;
    use libsecp256k1::{PublicKey, PublicKeyFormat};

    // ----------------------------------------------------------------------------------------
    // End-to-end EVM-compatibility regression for the full Schnorr-recovery verification path.
    // 12-node registry; 7 signers at bit positions 0, 2, 3, 4, 9, 10, 11 (signersBitmap = 3613).
    // ----------------------------------------------------------------------------------------

    const FIXTURE_REGISTERED_NODE_COUNT: u32 = 12;
    const FIXTURE_REGISTRY_VERSION: u32 = 12;
    const FIXTURE_SIGNATURES_REQUIRED: u32 = 5;
    const FIXTURE_REDUNDANCY_BUFFER: u8 = 2;
    const FIXTURE_CANONICAL_TIMESTAMP: u64 = 1_708_525_180;
    const FIXTURE_SIGNER_COUNT: u32 = 7;

    const FIXTURE_SOURCE_ID: [u8; 32] = [
        0x0b, 0x0c, 0x5c, 0x4a, 0x0e, 0x67, 0x58, 0x69, 0xda, 0xc2, 0x27, 0x2a, 0x40, 0x04, 0x63,
        0x65, 0xa2, 0x9c, 0x8a, 0xe7, 0x63, 0x5e, 0x52, 0xc4, 0x94, 0xd8, 0x40, 0xda, 0x2e, 0xc8,
        0x26, 0xcb,
    ];

    const FIXTURE_VALUE: [u8; 32] = [
        0xe1, 0xcd, 0x5b, 0x4f, 0x67, 0xac, 0xdc, 0x78, 0x68, 0xc3, 0xb1, 0x5f, 0x7b, 0x6c, 0xc2,
        0xdc, 0x27, 0x70, 0x54, 0x53, 0x71, 0x34, 0x2c, 0xab, 0x76, 0x62, 0x71, 0xbb, 0x3f, 0xd5,
        0xe7, 0x34,
    ];

    /// EVM `uint256(3613)` big-endian — bits 0, 2, 3, 4, 9, 10, 11 set.
    const FIXTURE_SIGNERS_BITMAP: [u8; 32] = [
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x0e, 0x1d,
    ];

    /// `schnorrSignature.signature` — the Schnorr scalar `s`.
    const FIXTURE_S: [u8; 32] = [
        0x1b, 0x8d, 0xd2, 0x78, 0xb3, 0x67, 0xb3, 0x4d, 0x4e, 0xce, 0x69, 0xb8, 0x8c, 0x28, 0xff,
        0x13, 0x01, 0xb6, 0x72, 0x51, 0xfc, 0x3d, 0x79, 0x26, 0xac, 0xb5, 0x25, 0xd1, 0x1f, 0xd3,
        0x17, 0x1d,
    ];

    /// `schnorrSignature.commitment` — Ethereum address (20 bytes).
    const FIXTURE_COMMITMENT: [u8; 20] = [
        0x51, 0xbe, 0x44, 0x69, 0x33, 0x1a, 0x9e, 0xb3, 0xed, 0x48, 0xb1, 0xd4, 0xe1, 0x1e, 0xc9,
        0xa0, 0xa5, 0x95, 0x2d, 0xf4,
    ];

    /// Full registry — compressed secp256k1 pubkeys for nodes 0–11.
    const FIXTURE_PUBKEYS: [[u8; 33]; 12] = [
        [
            0x03, 0x04, 0xb2, 0x3a, 0xff, 0xb9, 0xae, 0xb2, 0x80, 0xd6, 0xa2, 0x75, 0xb8, 0x65,
            0xe6, 0x3b, 0x1f, 0x27, 0xb0, 0xd5, 0x01, 0x6e, 0x35, 0x6d, 0xdb, 0xfe, 0x8b, 0xd2,
            0x5b, 0x27, 0xd1, 0x7e, 0x5f,
        ],
        [
            0x02, 0x1b, 0xdf, 0x3b, 0x69, 0xc5, 0x3c, 0x4e, 0xb2, 0xa9, 0x4c, 0x44, 0x3e, 0x68,
            0x65, 0x02, 0x68, 0x0f, 0xe3, 0x69, 0xd8, 0xba, 0xe5, 0xef, 0x02, 0x2b, 0x6e, 0x07,
            0xcc, 0xac, 0x05, 0xaa, 0x7d,
        ],
        [
            0x02, 0xdc, 0x2d, 0x88, 0xad, 0x9d, 0x1c, 0x4f, 0xc7, 0x6b, 0xc5, 0xaf, 0x00, 0xc3,
            0x90, 0x20, 0x08, 0xa0, 0xbe, 0x5f, 0x8f, 0x10, 0x48, 0xd1, 0xd5, 0xb3, 0xfb, 0xc7,
            0x19, 0xfc, 0x7a, 0xd5, 0xec,
        ],
        [
            0x02, 0xc2, 0x6e, 0xd5, 0xda, 0x51, 0x58, 0xfd, 0x27, 0xe5, 0xaf, 0xc0, 0x5f, 0x88,
            0xeb, 0xe4, 0x4b, 0xcb, 0xf0, 0x90, 0xae, 0x9b, 0xc5, 0xe7, 0x02, 0x4d, 0xf0, 0xd5,
            0x7e, 0xa4, 0xcd, 0x7a, 0x44,
        ],
        [
            0x02, 0x85, 0x07, 0x3b, 0x91, 0x57, 0xfb, 0xd6, 0x77, 0x95, 0x9b, 0xf9, 0x12, 0xac,
            0x07, 0x95, 0x8c, 0x4a, 0x62, 0x5d, 0xcc, 0xd7, 0x4f, 0xa1, 0x3c, 0x92, 0x9e, 0x3d,
            0xbb, 0x8d, 0x3d, 0xbd, 0x41,
        ],
        [
            0x02, 0x25, 0x50, 0xee, 0x49, 0x3c, 0x38, 0x43, 0x8a, 0xa7, 0x40, 0xc0, 0xa9, 0x97,
            0x8b, 0x20, 0x84, 0xa3, 0x50, 0x86, 0xbf, 0xef, 0x28, 0x9f, 0x3b, 0xe8, 0x58, 0xe2,
            0xe7, 0xda, 0x3c, 0x09, 0x7f,
        ],
        [
            0x03, 0x30, 0x96, 0x23, 0x4e, 0x51, 0x78, 0xf3, 0x71, 0x03, 0xa6, 0x6d, 0x86, 0x81,
            0x76, 0x02, 0x58, 0xdd, 0xc5, 0x2d, 0x1a, 0x06, 0xbd, 0xed, 0xa6, 0xaa, 0xa3, 0x2f,
            0xbe, 0x32, 0xb8, 0x78, 0x60,
        ],
        [
            0x03, 0xd4, 0xa4, 0x66, 0x9d, 0xbc, 0x8e, 0x33, 0x9a, 0x9c, 0x1d, 0xa3, 0x42, 0xf3,
            0x14, 0x54, 0x04, 0x92, 0x4c, 0x65, 0x1d, 0x94, 0x16, 0xb0, 0xb5, 0x8c, 0xc3, 0x0b,
            0x1f, 0xc8, 0x03, 0x7a, 0x92,
        ],
        [
            0x03, 0xfb, 0x7a, 0xae, 0x5c, 0x57, 0x4c, 0xd5, 0x0e, 0x2a, 0xd6, 0xed, 0x8e, 0x15,
            0x64, 0xa6, 0x70, 0x75, 0x56, 0xa1, 0x50, 0xa6, 0x4f, 0x24, 0x72, 0x67, 0xa2, 0x7d,
            0xe5, 0x9b, 0x82, 0xe2, 0x63,
        ],
        [
            0x02, 0x58, 0xbf, 0x41, 0xcf, 0xea, 0x2b, 0x1d, 0x34, 0x4c, 0xc3, 0x0b, 0xb7, 0x35,
            0xa1, 0x32, 0xc1, 0x75, 0x5b, 0x11, 0x2d, 0xb5, 0x8f, 0xaa, 0x7e, 0x4c, 0x44, 0x65,
            0x95, 0x2e, 0x00, 0x04, 0xbf,
        ],
        [
            0x02, 0x5d, 0xc1, 0x4d, 0x6b, 0xc2, 0x04, 0x42, 0xbe, 0x79, 0xf5, 0x1c, 0xf5, 0x20,
            0x33, 0xc3, 0x96, 0x7b, 0xcc, 0xdd, 0xc5, 0xd3, 0x66, 0x95, 0x95, 0x13, 0x73, 0x20,
            0xdf, 0xe5, 0xc6, 0xab, 0xfc,
        ],
        [
            0x03, 0xdc, 0xa6, 0x3a, 0x35, 0xd0, 0x48, 0xf7, 0x94, 0x5c, 0x95, 0x9d, 0x61, 0x8c,
            0x2f, 0xe8, 0xee, 0x5d, 0x40, 0x00, 0x29, 0x19, 0xa4, 0x6d, 0xff, 0x81, 0x27, 0x9c,
            0x04, 0xb9, 0x71, 0xe6, 0x06,
        ],
    ];

    fn fixture_payload() -> AttestationPayload {
        AttestationPayload {
            value: FIXTURE_VALUE,
            source_id: FIXTURE_SOURCE_ID,
            registry_version: FIXTURE_REGISTRY_VERSION,
            canonical_timestamp: FIXTURE_CANONICAL_TIMESTAMP,
            signatures_required: FIXTURE_SIGNATURES_REQUIRED,
        }
    }

    fn fixture_signature() -> SchnorrSignature {
        SchnorrSignature {
            agg_sig_s: FIXTURE_S,
            commitment_addr: FIXTURE_COMMITMENT,
            signers_bitmap: FIXTURE_SIGNERS_BITMAP,
        }
    }

    fn fixture_signers_xy() -> Vec<SignerXy> {
        use crate::bitmap::for_each_set_bit;
        let mut signers = Vec::new();
        for_each_set_bit(&FIXTURE_SIGNERS_BITMAP, |i| {
            let c = &FIXTURE_PUBKEYS[i];
            let pk = PublicKey::parse_slice(c, Some(PublicKeyFormat::Compressed))
                .expect("fixture pubkey must be a valid curve point");
            let full = pk.serialize();
            let x: [u8; 32] = full[1..33].try_into().unwrap();
            let y: [u8; 32] = full[33..65].try_into().unwrap();
            signers.push((x, y));
        });
        signers
    }

    fn fixture_signer_pubkeys_compressed() -> Vec<[u8; 33]> {
        use crate::bitmap::for_each_set_bit;
        let mut signers = Vec::new();
        for_each_set_bit(&FIXTURE_SIGNERS_BITMAP, |i| {
            signers.push(FIXTURE_PUBKEYS[i]);
        });
        signers
    }

    #[test]
    fn fixture_pubkeys_are_valid_curve_points() {
        for (i, pk) in FIXTURE_PUBKEYS.iter().enumerate() {
            PublicKey::parse_slice(pk, Some(PublicKeyFormat::Compressed))
                .unwrap_or_else(|_| panic!("fixture pubkey {i} is not a valid curve point"));
        }
    }

    #[test]
    fn fixture_signers_bitmap_popcount_meets_threshold() {
        use crate::bitmap::bitmap_popcount_evm;
        let popcount = bitmap_popcount_evm(&FIXTURE_SIGNERS_BITMAP);
        assert_eq!(popcount, FIXTURE_SIGNER_COUNT);
        assert!(popcount >= FIXTURE_SIGNATURES_REQUIRED);
    }

    /// The coalition-from-pubkeys path must match `PublicKey::combine`.
    #[test]
    fn reconstruct_coalition_key_matches_combine() {
        let signer_pubkeys = fixture_signer_pubkeys_compressed();
        let pks: Vec<PublicKey> = signer_pubkeys
            .iter()
            .map(|c| PublicKey::parse_slice(c, Some(PublicKeyFormat::Compressed)).unwrap())
            .collect();
        let combined = PublicKey::combine(&pks).unwrap().serialize_compressed();
        let got = reconstruct_coalition_key(&fixture_signers_xy()).unwrap();
        assert_eq!(got, combined);
        let got_c = reconstruct_coalition_key_compressed(&signer_pubkeys).unwrap();
        assert_eq!(got_c, combined);
    }

    fn fixture_attestation() -> Attestation {
        Attestation {
            payload: fixture_payload(),
            signature: fixture_signature(),
        }
    }

    /// Full end-to-end EVM-compat verification with caller-supplied pubkeys — no anchor, no PDAs.
    #[test]
    fn verify_attestation_accepts_evm_fixture() {
        let attestation = fixture_attestation();
        let signer_pubkeys = fixture_signer_pubkeys_compressed();
        verify_attestation(
            &attestation,
            FIXTURE_REGISTERED_NODE_COUNT,
            FIXTURE_REDUNDANCY_BUFFER,
            &fixture_signers_xy(),
        )
        .expect("fixture attestation must verify");
        verify_attestation_compressed(
            &attestation,
            FIXTURE_REGISTERED_NODE_COUNT,
            FIXTURE_REDUNDANCY_BUFFER,
            &signer_pubkeys,
        )
        .expect("compressed variant must verify");
    }

    #[test]
    fn tampered_s_fails_verification() {
        let mut attestation = fixture_attestation();
        attestation.signature.agg_sig_s[31] ^= 0x01;
        let res = verify_attestation(
            &attestation,
            FIXTURE_REGISTERED_NODE_COUNT,
            FIXTURE_REDUNDANCY_BUFFER,
            &fixture_signers_xy(),
        );
        assert_eq!(res, Err(AttestationError::InvalidAggregateSignature));
    }

    #[test]
    fn wrong_signer_count_is_rejected() {
        let attestation = fixture_attestation();
        let mut signers = fixture_signers_xy();
        signers.pop();
        assert_eq!(
            verify_attestation(
                &attestation,
                FIXTURE_REGISTERED_NODE_COUNT,
                FIXTURE_REDUNDANCY_BUFFER,
                &signers,
            ),
            Err(AttestationError::SignerCountMismatch)
        );
    }

    #[test]
    fn verify_aggregate_over_hash_roundtrip() {
        let payload = fixture_payload();
        let signature = fixture_signature();
        let signers = fixture_signers_xy();
        let message_hash = compute_message_hash(
            &payload,
            signature.signers_bitmap,
            payload.signatures_required,
        );
        assert!(verify_aggregate_over_hash(
            &signers,
            &signature.agg_sig_s,
            &signature.commitment_addr,
            &message_hash,
        )
        .unwrap());

        // Tampered hash → invalid (slashable), not an error.
        let mut bad_hash = message_hash;
        bad_hash[0] ^= 0xff;
        assert!(!verify_aggregate_over_hash(
            &signers,
            &signature.agg_sig_s,
            &signature.commitment_addr,
            &bad_hash,
        )
        .unwrap());
    }

    #[test]
    fn message_prefix_matches_known_constant() {
        // Guard against accidental edits to the domain-separation prefix.
        assert_eq!(MESSAGE_PREFIX[0], 0xa7);
    }
}
