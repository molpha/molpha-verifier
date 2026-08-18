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
    // Test vectors decoded from `tests/fixtures-json/verify-answer-evm.json`. End-to-end
    // EVM-compatibility regression for the full Schnorr-recovery verification path.
    // ----------------------------------------------------------------------------------------

    /// "solana-compat-job" right-padded to 32 bytes.
    const FIXTURE_SOURCE_ID: [u8; 32] = [
        0x73, 0x6f, 0x6c, 0x61, 0x6e, 0x61, 0x2d, 0x63, 0x6f, 0x6d, 0x70, 0x61, 0x74, 0x2d, 0x6a,
        0x6f, 0x62, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00,
    ];

    /// "solana-compat-val" right-padded to 32 bytes.
    const FIXTURE_VALUE: [u8; 32] = [
        0x73, 0x6f, 0x6c, 0x61, 0x6e, 0x61, 0x2d, 0x63, 0x6f, 0x6d, 0x70, 0x61, 0x74, 0x2d, 0x76,
        0x61, 0x6c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00,
    ];

    /// EVM `uint256(255)` big-endian — bits 0–7 set (8 signers).
    const FIXTURE_SIGNERS_BITMAP: [u8; 32] = [
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0xff,
    ];

    const FIXTURE_REGISTRY_VERSION: u32 = 1;
    const FIXTURE_SIGNATURES_REQUIRED: u32 = 8;
    const FIXTURE_CANONICAL_TIMESTAMP: u64 = 1_700_000_123;

    /// `schnorrSignature.signature` — the Schnorr scalar `s`.
    const FIXTURE_S: [u8; 32] = [
        0xc7, 0xe0, 0x99, 0x60, 0x3c, 0xee, 0xd2, 0xa1, 0x13, 0xd7, 0x5a, 0x9d, 0x95, 0xe2, 0x0f,
        0x92, 0x00, 0x6b, 0x06, 0xc5, 0x49, 0x7a, 0xdd, 0x09, 0x81, 0x7d, 0xa8, 0x90, 0x8d, 0x39,
        0x0d, 0xa5,
    ];

    /// `schnorrSignature.commitment` — Ethereum address (20 bytes).
    const FIXTURE_COMMITMENT: [u8; 20] = [
        0xc6, 0xb9, 0x4f, 0xea, 0x5d, 0xd5, 0xf9, 0x65, 0xd8, 0x67, 0x14, 0xb1, 0xd9, 0x9d, 0xcf,
        0xaf, 0x1e, 0x72, 0xee, 0x35,
    ];

    /// Compressed secp256k1 pubkeys for nodes at bit positions 0–7 (signersBitmap = 255).
    const FIXTURE_PUBKEYS: [[u8; 33]; 8] = [
        [
            0x03, 0xc0, 0x95, 0x27, 0xe9, 0x78, 0xf6, 0xea, 0x69, 0xf0, 0xc6, 0xb7, 0xac, 0x0f,
            0xb6, 0x3a, 0xd0, 0x81, 0xa8, 0xa2, 0x91, 0x15, 0x1c, 0x5a, 0x0b, 0x11, 0x5c, 0xce,
            0x43, 0x57, 0x51, 0xbe, 0x7d,
        ],
        [
            0x02, 0x64, 0xa7, 0x27, 0x04, 0xf3, 0x9f, 0x8d, 0xd1, 0x7f, 0x20, 0xd7, 0x1c, 0x5b,
            0x21, 0xf3, 0x7b, 0x58, 0x52, 0x65, 0x6b, 0xc0, 0x55, 0x54, 0x42, 0xbf, 0x72, 0x72,
            0x22, 0xf2, 0x9d, 0x7e, 0x58,
        ],
        [
            0x02, 0x75, 0xae, 0x1e, 0x3d, 0xac, 0x00, 0xeb, 0x7d, 0xf0, 0x2e, 0x9f, 0xe8, 0xd9,
            0x70, 0x9c, 0x8a, 0x2c, 0x09, 0xa1, 0x1e, 0xd4, 0xf7, 0xd9, 0xaa, 0x46, 0xa7, 0xde,
            0xa6, 0xcf, 0x37, 0x6d, 0x7f,
        ],
        [
            0x02, 0x6c, 0xe2, 0x5b, 0x3a, 0x16, 0x1a, 0xb8, 0xe0, 0xf0, 0x5e, 0x4c, 0xd1, 0xc7,
            0x7b, 0x77, 0x69, 0x6d, 0x26, 0xc6, 0x41, 0xeb, 0xde, 0xa4, 0xe8, 0x1a, 0xa8, 0x9a,
            0x90, 0xf3, 0x2c, 0xfc, 0x54,
        ],
        [
            0x03, 0x5b, 0x95, 0xd7, 0x03, 0x22, 0x8b, 0xef, 0xcc, 0xc3, 0x78, 0x62, 0x9d, 0xc1,
            0x98, 0x04, 0xce, 0xfe, 0x56, 0xc3, 0x3c, 0x64, 0x5f, 0xa4, 0xbc, 0x1a, 0xa0, 0xf3,
            0x75, 0xe3, 0xb4, 0xfa, 0x5e,
        ],
        [
            0x03, 0x99, 0x5e, 0x4b, 0xe0, 0xec, 0xd4, 0x22, 0xbf, 0x25, 0x0a, 0x3d, 0xa3, 0xa0,
            0xb8, 0x34, 0x2e, 0x52, 0x89, 0x3a, 0x3e, 0x06, 0x4f, 0xa6, 0x35, 0x55, 0x73, 0x78,
            0xb5, 0x9a, 0xfa, 0x8b, 0x50,
        ],
        [
            0x03, 0xec, 0x90, 0x6d, 0x0a, 0x1c, 0xfc, 0x3c, 0x7d, 0xec, 0x18, 0x08, 0x8c, 0x3d,
            0x14, 0x4f, 0x32, 0x15, 0x80, 0xec, 0xe0, 0xa6, 0xba, 0xe5, 0xce, 0xb2, 0x8d, 0xcf,
            0x8d, 0xc6, 0xe3, 0xda, 0x03,
        ],
        [
            0x03, 0x27, 0x5f, 0xcf, 0x98, 0x38, 0xb4, 0x7a, 0xac, 0xff, 0x25, 0x1f, 0x4f, 0x09,
            0x9f, 0x80, 0xc6, 0x4a, 0x1a, 0x9a, 0xed, 0xbd, 0xb6, 0x28, 0xc2, 0xc8, 0x7f, 0x2c,
            0x5e, 0x12, 0x3d, 0xd0, 0x40,
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
        FIXTURE_PUBKEYS
            .iter()
            .map(|c| {
                let pk = PublicKey::parse_slice(c, Some(PublicKeyFormat::Compressed))
                    .expect("fixture pubkey must be a valid curve point");
                let full = pk.serialize();
                let x: [u8; 32] = full[1..33].try_into().unwrap();
                let y: [u8; 32] = full[33..65].try_into().unwrap();
                (x, y)
            })
            .collect()
    }

    #[test]
    fn fixture_pubkeys_are_valid_curve_points() {
        for (i, pk) in FIXTURE_PUBKEYS.iter().enumerate() {
            PublicKey::parse_slice(pk, Some(PublicKeyFormat::Compressed))
                .unwrap_or_else(|_| panic!("fixture pubkey {i} is not a valid curve point"));
        }
    }

    #[test]
    fn fixture_signers_bitmap_popcount_is_8() {
        use crate::bitmap::bitmap_popcount_evm;
        assert_eq!(
            bitmap_popcount_evm(&FIXTURE_SIGNERS_BITMAP),
            FIXTURE_SIGNATURES_REQUIRED
        );
    }

    /// The coalition-from-pubkeys path must match `PublicKey::combine`.
    #[test]
    fn reconstruct_coalition_key_matches_combine() {
        let pks: Vec<PublicKey> = FIXTURE_PUBKEYS
            .iter()
            .map(|c| PublicKey::parse_slice(c, Some(PublicKeyFormat::Compressed)).unwrap())
            .collect();
        let combined = PublicKey::combine(&pks).unwrap().serialize_compressed();
        let got = reconstruct_coalition_key(&fixture_signers_xy()).unwrap();
        assert_eq!(got, combined);
        let got_c = reconstruct_coalition_key_compressed(&FIXTURE_PUBKEYS).unwrap();
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
        // node_count == signatures_required == 8 → selection is the full set, signers ⊆ selection.
        verify_attestation(&attestation, 8, 0, &fixture_signers_xy())
            .expect("fixture attestation must verify");
        verify_attestation_compressed(&attestation, 8, 0, &FIXTURE_PUBKEYS)
            .expect("compressed variant must verify");
    }

    #[test]
    fn tampered_s_fails_verification() {
        let mut attestation = fixture_attestation();
        attestation.signature.agg_sig_s[31] ^= 0x01;
        let res = verify_attestation(&attestation, 8, 0, &fixture_signers_xy());
        assert_eq!(res, Err(AttestationError::InvalidAggregateSignature));
    }

    #[test]
    fn wrong_signer_count_is_rejected() {
        let attestation = fixture_attestation();
        let mut signers = fixture_signers_xy();
        signers.pop();
        assert_eq!(
            verify_attestation(&attestation, 8, 0, &signers),
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
