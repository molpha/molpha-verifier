//! Attestation verification over caller-supplied signer pubkeys.
//!
//! Pure: the caller resolves pubkeys and passes them in. No account I/O.

use solana_secp256k1_recover::secp256k1_recover;

use crate::bitmap::Bitmap;
use crate::coalition::{CoalitionAccumulator, CoalitionKey};
use crate::error::AttestationError;
use crate::message::compute_message_hash;
use crate::payload::Attestation;
use crate::scalar::{
    eth_address_from_uncompressed_pubkey, evm_schnorr_ecdsa_inputs,
    secp256k1_scalar_is_valid_nonzero,
};
use crate::selection::verify_selection;
use crate::state::{RegistryView, SignerXy};

/// Verify an attestation against caller-supplied signer pubkeys.
///
/// # Caller contract
/// - `node_count` is the registry size for `attestation.payload.registry_version`.
/// - `ordered_signers`: one `(x, y)` per set bit of `signers_bitmap`, ascending bit-index order.
///   This function trusts the supplied set.
///
/// Re-derives the selection bitmap and enforces `signers ⊆ selection`. Checks run cheapest-first
/// (version → scalar → count → selection → coalition → hash → recovery).
///
/// Normalizes the coalition key with a field inversion; see [`verify_with_coalition_key`] for
/// the cheaper keyed path.
pub fn verify(
    attestation: &Attestation,
    ordered_signers: &[SignerXy],
    registry: &RegistryView,
) -> Result<(), AttestationError> {
    verify_inner(attestation, ordered_signers, registry, None)
}

/// [`verify`] with the affine coalition key supplied instead of computed.
///
/// `coalition_key` is untrusted and not part of the signed message. It replaces the field
/// inversion with a projective check against the verifier's own sum (see
/// [`CoalitionAccumulator::compressed_pubkey_with_key`]); compute it with [`coalition_key`] or
/// any secp256k1 point sum over the same signers. A wrong key fails with
/// [`AttestationError::InvalidCoalitionKey`].
pub fn verify_with_coalition_key(
    attestation: &Attestation,
    ordered_signers: &[SignerXy],
    registry: &RegistryView,
    coalition_key: &CoalitionKey,
) -> Result<(), AttestationError> {
    verify_inner(attestation, ordered_signers, registry, Some(coalition_key))
}

#[inline(always)]
fn verify_inner(
    attestation: &Attestation,
    ordered_signers: &[SignerXy],
    registry: &RegistryView,
    coalition_key: Option<&CoalitionKey>,
) -> Result<(), AttestationError> {
    if attestation.payload.registry_version != registry.version {
        return Err(AttestationError::InvalidRegistryVersion);
    }

    let signature = &attestation.signature;

    if !secp256k1_scalar_is_valid_nonzero(&signature.agg_sig_s) {
        return Err(AttestationError::InvalidAggregateSignature);
    }

    let signer_count = Bitmap::load(&signature.signers_bitmap).popcount();
    if signer_count != ordered_signers.len() as u32 {
        return Err(AttestationError::SignerCountMismatch);
    }

    if !verify_selection(
        &attestation.payload.source_id,
        attestation.payload.canonical_timestamp,
        attestation.payload.signatures_required,
        registry,
        &signature.signers_bitmap,
    )? {
        return Err(AttestationError::SignersNotSubsetOfSelection);
    }

    let x_coalition = compressed_coalition_key(ordered_signers, coalition_key)?;
    let message_hash = compute_message_hash(&attestation.payload, signature.signers_bitmap);

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

/// Reconstruct coalition key `Σ X_i` as compressed pubkey (33 bytes).
///
/// Errors on an empty set or a point-at-infinity sum.
pub fn reconstruct_coalition_key(
    ordered_signers: &[SignerXy],
) -> Result<[u8; 33], AttestationError> {
    accumulate_coalition(ordered_signers)?.compressed_pubkey()
}

/// Off-chain helper: the affine [`CoalitionKey`] accepted by the `*_with_coalition_key` paths.
///
/// A property of the point `Σ X_i`, so any signer order (and any secp256k1 library) gives the
/// same value. Errors on an empty set or a point-at-infinity sum.
pub fn coalition_key(signers: &[SignerXy]) -> Result<CoalitionKey, AttestationError> {
    accumulate_coalition(signers)?.coalition_key()
}

#[inline(always)]
fn accumulate_coalition(
    ordered_signers: &[SignerXy],
) -> Result<CoalitionAccumulator, AttestationError> {
    if ordered_signers.is_empty() {
        return Err(AttestationError::InvalidSignersBitmap);
    }
    let mut coalition = CoalitionAccumulator::default();
    for (x, y) in ordered_signers {
        coalition.add_stored_xy(x, y)?;
    }
    Ok(coalition)
}

/// Compressed `Σ X_i`, checked against `coalition_key` when supplied, else inverted.
#[inline(always)]
fn compressed_coalition_key(
    ordered_signers: &[SignerXy],
    coalition_key: Option<&CoalitionKey>,
) -> Result<[u8; 33], AttestationError> {
    let coalition = accumulate_coalition(ordered_signers)?;
    match coalition_key {
        Some(key) => coalition.compressed_pubkey_with_key(key),
        None => coalition.compressed_pubkey(),
    }
}

/// Verify an aggregate Schnorr signature over `message_hash` for `ordered_signers`.
pub fn verify_aggregate_over_hash(
    agg_sig_s: &[u8; 32],
    commitment: &[u8; 20],
    message_hash: &[u8; 32],
    ordered_signers: &[SignerXy],
) -> Result<bool, AttestationError> {
    verify_aggregate_over_hash_inner(agg_sig_s, commitment, message_hash, ordered_signers, None)
}

/// [`verify_aggregate_over_hash`] with the affine coalition key supplied instead of computed.
///
/// A wrong key is an input error (`Err(InvalidCoalitionKey)`), never an `Ok(false)` verdict:
/// it says nothing about the signature.
pub fn verify_aggregate_over_hash_with_coalition_key(
    agg_sig_s: &[u8; 32],
    commitment: &[u8; 20],
    message_hash: &[u8; 32],
    ordered_signers: &[SignerXy],
    coalition_key: &CoalitionKey,
) -> Result<bool, AttestationError> {
    verify_aggregate_over_hash_inner(
        agg_sig_s,
        commitment,
        message_hash,
        ordered_signers,
        Some(coalition_key),
    )
}

#[inline(always)]
fn verify_aggregate_over_hash_inner(
    agg_sig_s: &[u8; 32],
    commitment: &[u8; 20],
    message_hash: &[u8; 32],
    ordered_signers: &[SignerXy],
    coalition_key: Option<&CoalitionKey>,
) -> Result<bool, AttestationError> {
    if !secp256k1_scalar_is_valid_nonzero(agg_sig_s) {
        return Ok(false);
    }

    let x_coalition = compressed_coalition_key(ordered_signers, coalition_key)?;
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
        use crate::bitmap::{for_each_set_bit, Bitmap};
        let mut signers = Vec::new();
        for_each_set_bit(Bitmap::load(&SIGNERS_BITMAP), |i| {
            signers.push(PUBKEYS[i]);
            Ok::<(), AttestationError>(())
        })
        .unwrap();
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
        use crate::bitmap::Bitmap;
        let popcount = Bitmap::load(&SIGNERS_BITMAP).popcount();
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

    fn fixture_registry() -> RegistryView<'static> {
        RegistryView {
            version: REGISTRY_VERSION,
            node_count: REGISTERED_NODE_COUNT as u16,
            redundancy_buffer: REDUNDANCY_BUFFER,
            nodes: &[],
        }
    }

    #[test]
    fn verify_attestation_accepts_fixture() {
        let attestation = fixture_attestation();
        verify(&attestation, &fixture_signers_xy(), &fixture_registry())
            .expect("fixture attestation must verify");
    }

    #[test]
    fn tampered_s_fails_verification() {
        let mut attestation = fixture_attestation();
        attestation.signature.agg_sig_s[31] ^= 0x01;
        let res = verify(&attestation, &fixture_signers_xy(), &fixture_registry());
        assert_eq!(res, Err(AttestationError::InvalidAggregateSignature));
    }

    #[test]
    fn wrong_signer_count_is_rejected() {
        let attestation = fixture_attestation();
        let mut signers = fixture_signers_xy();
        signers.pop();
        assert_eq!(
            verify(&attestation, &signers, &fixture_registry()),
            Err(AttestationError::SignerCountMismatch)
        );
    }

    #[test]
    fn wrong_registry_version_is_rejected() {
        let attestation = fixture_attestation();
        let mut registry = fixture_registry();
        registry.version = REGISTRY_VERSION + 1;
        assert_eq!(
            verify(&attestation, &fixture_signers_xy(), &registry),
            Err(AttestationError::InvalidRegistryVersion)
        );
    }

    #[test]
    fn verify_aggregate_over_hash_roundtrip() {
        let attestation = fixture_attestation();
        let signers = fixture_signers_xy();
        let message_hash =
            compute_message_hash(&attestation.payload, attestation.signature.signers_bitmap);
        assert!(verify_aggregate_over_hash(
            &attestation.signature.agg_sig_s,
            &attestation.signature.commitment,
            &message_hash,
            &fixture_signers_xy(),
        )
        .unwrap());

        let mut bad_hash = message_hash;
        bad_hash[0] ^= 0xff;
        assert!(!verify_aggregate_over_hash(
            &attestation.signature.agg_sig_s,
            &attestation.signature.commitment,
            &bad_hash,
            &signers,
        )
        .unwrap());
    }

    #[test]
    fn verify_with_coalition_key_accepts_fixture_key() {
        let attestation = fixture_attestation();
        let signers = fixture_signers_xy();
        let key = coalition_key(&signers).unwrap();
        verify_with_coalition_key(&attestation, &signers, &fixture_registry(), &key)
            .expect("keyed verification must accept the fixture");
    }

    #[test]
    fn verify_with_coalition_key_rejects_wrong_keys() {
        let attestation = fixture_attestation();
        let signers = fixture_signers_xy();
        let key = coalition_key(&signers).unwrap();

        let mut flipped = key;
        flipped.x[31] ^= 0x01;
        // A real key, but of a different signer set.
        let subset = coalition_key(&signers[1..]).unwrap();
        let single = CoalitionKey {
            x: signers[0].0,
            y: signers[0].1,
        };
        let zero = CoalitionKey {
            x: [0u8; 32],
            y: [0u8; 32],
        };

        for bad in [flipped, subset, single, zero] {
            assert_eq!(
                verify_with_coalition_key(&attestation, &signers, &fixture_registry(), &bad),
                Err(AttestationError::InvalidCoalitionKey),
                "key {bad:02x?} must be rejected"
            );
        }
    }

    #[test]
    fn coalition_key_is_independent_of_signer_order() {
        let signers = fixture_signers_xy();
        let mut reversed = signers.clone();
        reversed.reverse();
        let key = coalition_key(&signers).unwrap();
        assert_eq!(key, coalition_key(&reversed).unwrap());

        let compressed = reconstruct_coalition_key(&signers).unwrap();
        assert_eq!(compressed[1..], key.x);
        assert_eq!(compressed[0] & 1, key.y[31] & 1);
    }

    #[test]
    fn keyed_verification_still_checks_the_signature() {
        let mut attestation = fixture_attestation();
        attestation.signature.agg_sig_s[31] ^= 0x01;
        let signers = fixture_signers_xy();
        let key = coalition_key(&signers).unwrap();
        assert_eq!(
            verify_with_coalition_key(&attestation, &signers, &fixture_registry(), &key),
            Err(AttestationError::InvalidAggregateSignature)
        );
    }

    #[test]
    fn keyed_aggregate_over_hash_separates_verdicts_from_bad_keys() {
        let attestation = fixture_attestation();
        let signers = fixture_signers_xy();
        let key = coalition_key(&signers).unwrap();
        let message_hash = attestation.message_hash();
        let (s, commitment) = (
            &attestation.signature.agg_sig_s,
            &attestation.signature.commitment,
        );

        assert_eq!(
            verify_aggregate_over_hash_with_coalition_key(
                s,
                commitment,
                &message_hash,
                &signers,
                &key
            ),
            Ok(true)
        );

        let mut bad_hash = message_hash;
        bad_hash[0] ^= 0xff;
        assert_eq!(
            verify_aggregate_over_hash_with_coalition_key(s, commitment, &bad_hash, &signers, &key),
            Ok(false)
        );

        let mut bad_key = key;
        bad_key.y[0] ^= 0x01;
        assert_eq!(
            verify_aggregate_over_hash_with_coalition_key(
                s,
                commitment,
                &message_hash,
                &signers,
                &bad_key
            ),
            Err(AttestationError::InvalidCoalitionKey)
        );
    }

    #[test]
    fn message_prefix_matches_known_constant() {
        assert_eq!(MESSAGE_PREFIX[0], 0xa7);
    }
}
