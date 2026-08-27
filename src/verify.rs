//! Attestation verification over caller-supplied signer pubkeys.
//!
//! Pure: the caller resolves pubkeys and passes them in. No account I/O.

use solana_secp256k1_recover::secp256k1_recover;

use crate::bitmap::{bitmap_is_subset_u256, bitmap_load};
use crate::coalition::CoalitionAccumulator;
use crate::error::AttestationError;
use crate::message::compute_message_hash;
use crate::payload::Attestation;
use crate::scalar::{
    eth_address_from_uncompressed_pubkey, evm_schnorr_ecdsa_inputs,
    secp256k1_scalar_is_valid_nonzero,
};
use crate::selection::derive_selection_bitmap_u256;

/// Secp256k1 affine coordinates `(x, y)`, big-endian.
pub type SignerXy = ([u8; 32], [u8; 32]);

/// Verify an attestation against caller-supplied signer pubkeys.
///
/// # Caller contract
/// - `node_count` is the registry size for `attestation.payload.registry_version`.
/// - `ordered_signers`: one `(x, y)` per set bit of `signers_bitmap`, ascending bit-index order.
///   This function trusts the supplied set.
///
/// Re-derives the selection bitmap and enforces `signers ⊆ selection`. Checks run cheapest-first
/// (scalar → threshold → count → selection → coalition → hash → recovery); acceptance is unchanged.
pub fn verify_attestation(
    attestation: &Attestation,
    node_count: u32,
    redundancy_buffer: u8,
    ordered_signers: &[SignerXy],
) -> Result<(), AttestationError> {
    verify_attestation_core(
        attestation,
        node_count,
        redundancy_buffer,
        ordered_signers.len(),
        |coalition| accumulate_xy(ordered_signers, coalition),
    )
}

pub(crate) fn verify_attestation_core<F>(
    attestation: &Attestation,
    node_count: u32,
    redundancy_buffer: u8,
    supplied_signers: usize,
    accumulate: F,
) -> Result<(), AttestationError>
where
    F: FnOnce(&mut CoalitionAccumulator) -> Result<(), AttestationError>,
{
    let signature = &attestation.signature;
    let payload = &attestation.payload;

    if !secp256k1_scalar_is_valid_nonzero(&signature.agg_sig_s) {
        return Err(AttestationError::InvalidAggregateSignature);
    }

    let signers = bitmap_load(&signature.signers_bitmap);
    let signer_count = signers.count_ones();
    if signer_count < u32::from(payload.signatures_required) {
        return Err(AttestationError::InsufficientSigners);
    }

    // Cheap count check before keccak-heavy selection derivation.
    if supplied_signers != signer_count as usize {
        return Err(AttestationError::SignerCountMismatch);
    }
    if signer_count == 0 {
        return Err(AttestationError::InvalidSignersBitmap);
    }

    let expected_selection = derive_selection_bitmap_u256(
        &payload.source_id,
        payload.registry_version,
        payload.canonical_timestamp,
        node_count,
        payload.signatures_required,
        redundancy_buffer,
    )?;
    if !bitmap_is_subset_u256(signers, expected_selection) {
        return Err(AttestationError::SignersNotSubsetOfSelection);
    }

    let mut coalition = CoalitionAccumulator::default();
    accumulate(&mut coalition)?;
    let x_coalition = coalition.compressed_pubkey()?;

    let message_hash = compute_message_hash(payload, signature.signers_bitmap);

    if recover_and_match(
        &x_coalition,
        &message_hash,
        &signature.agg_sig_s,
        &signature.commitment,
    ) {
        Ok(())
    } else {
        Err(AttestationError::InvalidAggregateSignature)
    }
}

fn accumulate_xy(
    ordered_signers: &[SignerXy],
    coalition: &mut CoalitionAccumulator,
) -> Result<(), AttestationError> {
    for (x, y) in ordered_signers {
        coalition.add_stored_xy(x, y)?;
    }
    Ok(())
}

/// Reconstruct coalition key `Σ X_i` as compressed pubkey (33 bytes).
///
/// Errors on an empty set or a point-at-infinity sum.
pub fn reconstruct_coalition_key(
    ordered_signers: &[SignerXy],
) -> Result<[u8; 33], AttestationError> {
    if ordered_signers.is_empty() {
        return Err(AttestationError::InvalidSignersBitmap);
    }
    let mut coalition = CoalitionAccumulator::default();
    accumulate_xy(ordered_signers, &mut coalition)?;
    coalition.compressed_pubkey()
}

/// Verify an aggregate Schnorr signature over `message_hash` for `ordered_signers`.
///
/// `Ok(true)` = valid, `Ok(false)` = invalid (slashable), `Err` = malformed input.
pub fn verify_aggregate_over_hash(
    ordered_signers: &[SignerXy],
    agg_sig_s: &[u8; 32],
    commitment: &[u8; 20],
    message_hash: &[u8; 32],
) -> Result<bool, AttestationError> {
    verify_aggregate_over_hash_core(
        agg_sig_s,
        commitment,
        message_hash,
        ordered_signers.len(),
        |coalition| accumulate_xy(ordered_signers, coalition),
    )
}

/// [`verify_aggregate_over_hash`] with a folding closure over the coalition accumulator.
pub(crate) fn verify_aggregate_over_hash_core<F>(
    agg_sig_s: &[u8; 32],
    commitment: &[u8; 20],
    message_hash: &[u8; 32],
    supplied_signers: usize,
    accumulate: F,
) -> Result<bool, AttestationError>
where
    F: FnOnce(&mut CoalitionAccumulator) -> Result<(), AttestationError>,
{
    if !secp256k1_scalar_is_valid_nonzero(agg_sig_s) {
        return Ok(false);
    }
    if supplied_signers == 0 {
        return Err(AttestationError::InvalidSignersBitmap);
    }
    let mut coalition = CoalitionAccumulator::default();
    accumulate(&mut coalition)?;
    let x_coalition = coalition.compressed_pubkey()?;
    Ok(recover_and_match(
        &x_coalition,
        message_hash,
        agg_sig_s,
        commitment,
    ))
}

fn recover_and_match(
    x_coalition: &[u8; 33],
    message_hash: &[u8; 32],
    agg_sig_s: &[u8; 32],
    commitment: &[u8; 20],
) -> bool {
    let (recovery_id, ecdsa_signature, ecdsa_hash) =
        match evm_schnorr_ecdsa_inputs(x_coalition, message_hash, agg_sig_s, commitment) {
            Ok(v) => v,
            Err(_) => return false,
        };
    let recovered = match secp256k1_recover(&ecdsa_hash, recovery_id, &ecdsa_signature) {
        Ok(r) => r,
        Err(_) => return false,
    };
    eth_address_from_uncompressed_pubkey(recovered.to_bytes()) == *commitment
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::coalition::public_key_from_affine_xy;
    use crate::fixtures::{
        CANONICAL_TIMESTAMP, COMMITMENT, PUBKEYS, REDUNDANCY_BUFFER, REGISTERED_NODE_COUNT,
        REGISTRY_VERSION, S, SIGNATURES_REQUIRED, SIGNERS_BITMAP, SIGNER_COUNT, SOURCE_ID, VALUE,
    };
    use crate::message::MESSAGE_PREFIX;
    use libsecp256k1::PublicKey;

    fn fixture_signers_xy() -> Vec<SignerXy> {
        use crate::bitmap::for_each_set_bit;
        let mut signers = Vec::new();
        for_each_set_bit(&SIGNERS_BITMAP, |i| {
            signers.push(PUBKEYS[i]);
        });
        signers
    }

    #[test]
    fn fixture_pubkeys_are_valid_curve_points() {
        let mut scratch = [0u8; 65];
        for (i, (x, y)) in PUBKEYS.iter().enumerate() {
            public_key_from_affine_xy(&mut scratch, x, y)
                .unwrap_or_else(|_| panic!("fixture pubkey {i} is not a valid curve point"));
        }
    }

    #[test]
    fn fixture_signers_bitmap_popcount_meets_threshold() {
        use crate::bitmap::bitmap_popcount;
        let popcount = bitmap_popcount(&SIGNERS_BITMAP);
        assert_eq!(popcount, SIGNER_COUNT);
        assert!(popcount >= u32::from(SIGNATURES_REQUIRED));
    }

    #[test]
    fn reconstruct_coalition_key_matches_combine() {
        let signer_pubkeys = fixture_signers_xy();
        let mut scratch = [0u8; 65];
        let pks: Vec<PublicKey> = signer_pubkeys
            .iter()
            .map(|(x, y)| public_key_from_affine_xy(&mut scratch, x, y).unwrap())
            .collect();
        let combined = PublicKey::combine(&pks).unwrap().serialize_compressed();
        let got = reconstruct_coalition_key(&signer_pubkeys).unwrap();
        assert_eq!(got, combined);
    }

    fn fixture_attestation() -> Attestation {
        Attestation {
            payload: crate::payload::AttestationPayload {
                value: VALUE,
                source_id: SOURCE_ID,
                registry_version: REGISTRY_VERSION,
                canonical_timestamp: CANONICAL_TIMESTAMP,
                signatures_required: SIGNATURES_REQUIRED,
            },
            signature: crate::payload::SchnorrSignature {
                agg_sig_s: S,
                commitment: COMMITMENT,
                signers_bitmap: SIGNERS_BITMAP,
            },
        }
    }

    #[test]
    fn verify_attestation_accepts_fixture() {
        let attestation = fixture_attestation();
        verify_attestation(
            &attestation,
            REGISTERED_NODE_COUNT,
            REDUNDANCY_BUFFER,
            &fixture_signers_xy(),
        )
        .expect("fixture attestation must verify");
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
        let attestation = fixture_attestation();
        let signers = fixture_signers_xy();
        let message_hash =
            compute_message_hash(&attestation.payload, attestation.signature.signers_bitmap);
        assert!(verify_aggregate_over_hash(
            &signers,
            &attestation.signature.agg_sig_s,
            &attestation.signature.commitment,
            &message_hash,
        )
        .unwrap());

        let mut bad_hash = message_hash;
        bad_hash[0] ^= 0xff;
        assert!(!verify_aggregate_over_hash(
            &signers,
            &attestation.signature.agg_sig_s,
            &attestation.signature.commitment,
            &bad_hash,
        )
        .unwrap());
    }

    #[test]
    fn message_prefix_matches_known_constant() {
        assert_eq!(MESSAGE_PREFIX[0], 0xa7);
    }
}
