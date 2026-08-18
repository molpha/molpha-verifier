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
    if signer_count < u32::from(payload.signatures_required) {
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
    let message_hash = compute_message_hash(payload, signature.signers_bitmap);

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
    use crate::fixtures::{
        CANONICAL_TIMESTAMP, COMMITMENT, PUBKEYS, REDUNDANCY_BUFFER, REGISTERED_NODE_COUNT,
        REGISTRY_VERSION, S, SIGNATURES_REQUIRED, SIGNERS_BITMAP, SIGNER_COUNT, SOURCE_ID, VALUE,
    };
    use crate::message::MESSAGE_PREFIX;
    use libsecp256k1::{PublicKey, PublicKeyFormat};

    fn fixture_payload() -> AttestationPayload {
        AttestationPayload {
            value: VALUE,
            source_id: SOURCE_ID,
            registry_version: REGISTRY_VERSION,
            canonical_timestamp: CANONICAL_TIMESTAMP,
            signatures_required: SIGNATURES_REQUIRED,
        }
    }

    fn fixture_signature() -> SchnorrSignature {
        SchnorrSignature {
            agg_sig_s: S,
            commitment_addr: COMMITMENT,
            signers_bitmap: SIGNERS_BITMAP,
        }
    }

    fn fixture_signers_xy() -> Vec<SignerXy> {
        use crate::bitmap::for_each_set_bit;
        let mut signers = Vec::new();
        for_each_set_bit(&SIGNERS_BITMAP, |i| {
            let c = &PUBKEYS[i];
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
        for_each_set_bit(&SIGNERS_BITMAP, |i| {
            signers.push(PUBKEYS[i]);
        });
        signers
    }

    #[test]
    fn fixture_pubkeys_are_valid_curve_points() {
        for (i, pk) in PUBKEYS.iter().enumerate() {
            PublicKey::parse_slice(pk, Some(PublicKeyFormat::Compressed))
                .unwrap_or_else(|_| panic!("fixture pubkey {i} is not a valid curve point"));
        }
    }

    #[test]
    fn fixture_signers_bitmap_popcount_meets_threshold() {
        use crate::bitmap::bitmap_popcount_evm;
        let popcount = bitmap_popcount_evm(&SIGNERS_BITMAP);
        assert_eq!(popcount, SIGNER_COUNT);
        assert!(popcount >= u32::from(SIGNATURES_REQUIRED));
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
            REGISTERED_NODE_COUNT,
            REDUNDANCY_BUFFER,
            &fixture_signers_xy(),
        )
        .expect("fixture attestation must verify");
        verify_attestation_compressed(
            &attestation,
            REGISTERED_NODE_COUNT,
            REDUNDANCY_BUFFER,
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
            REGISTERED_NODE_COUNT,
            REDUNDANCY_BUFFER,
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
                REGISTERED_NODE_COUNT,
                REDUNDANCY_BUFFER,
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
        let message_hash = compute_message_hash(&payload, signature.signers_bitmap);
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
