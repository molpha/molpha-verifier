//! Attestation verification.
//!
//! Pure: signer keys come from the [`RegistryView`] the caller passes in. No account I/O.

use solana_secp256k1_recover::secp256k1_recover;

use crate::bitmap::{for_each_set_bit, Bitmap};
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

/// Verify an attestation against the registry snapshot it names.
///
/// # Caller contract
/// `registry` is the snapshot for `attestation.payload.registry_version`, with its member table.
/// Each set bit of `signers_bitmap` binds to `registry.nodes[bit]`, whose key is used as is.
///
/// Re-derives the selection bitmap and enforces `signers ⊆ selection`. Checks run cheapest-first
/// (version → scalar → selection → coalition → hash → recovery).
///
/// `coalition_key` is untrusted and not part of the signed message. When supplied it replaces
/// the field inversion with a projective check against the verifier's own sum (see
/// [`CoalitionAccumulator::compressed_pubkey_with_key`]); compute it with [`coalition_key`] or
/// any secp256k1 point sum over the same signers. A wrong key fails with
/// [`AttestationError::InvalidCoalitionKey`]. `None` normalizes with a field inversion.
pub fn verify(
    attestation: &Attestation,
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

    if !verify_selection(
        &attestation.payload.source_id,
        attestation.payload.timestamp,
        attestation.payload.signatures_required,
        registry,
        &signature.signers_bitmap,
    )? {
        return Err(AttestationError::SignersNotSubsetOfSelection);
    }

    let coalition = accumulate_registry_signers(registry, &signature.signers_bitmap)?;
    let x_coalition = compress_coalition(&coalition, coalition_key)?;
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

/// `Σ X_i` over the registry keys at the set bits of `signers_bitmap`, without collecting them.
///
/// Errors on an empty bitmap or a bit outside the registry.
#[inline(always)]
pub(crate) fn accumulate_registry_signers(
    registry: &RegistryView,
    signers_bitmap: &[u8; 32],
) -> Result<CoalitionAccumulator, AttestationError> {
    let signers = Bitmap::load(signers_bitmap);
    if signers == Bitmap::EMPTY {
        return Err(AttestationError::InvalidSignersBitmap);
    }
    let mut coalition = CoalitionAccumulator::default();
    for_each_set_bit(signers, |bit| {
        let node = registry.signer(bit)?;
        coalition.add_stored_xy(&node.x, &node.y)
    })?;
    Ok(coalition)
}

/// Compressed `Σ X_i`, checked against `coalition_key` when supplied, else inverted.
#[inline(always)]
pub(crate) fn compress_coalition(
    coalition: &CoalitionAccumulator,
    coalition_key: Option<&CoalitionKey>,
) -> Result<[u8; 33], AttestationError> {
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

    let coalition = accumulate_coalition(ordered_signers)?;
    let x_coalition = compress_coalition(&coalition, coalition_key)?;
    Ok(recover_and_match(
        &x_coalition,
        message_hash,
        agg_sig_s,
        commitment,
    ))
}

pub(crate) fn recover_and_match(
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
        COMMITMENT, PUBKEYS, REDUNDANCY_BUFFER, REGISTERED_NODE_COUNT, REGISTRY_VERSION, S,
        SIGNATURES_REQUIRED, SIGNERS_BITMAP, SIGNER_COUNT, SOURCE_ID, TIMESTAMP, VALUE,
    };
    use crate::message::MESSAGE_PREFIX;
    use crate::state::{NodeEntry, MAX_REGISTRY_NODES};
    use libsecp256k1::PublicKey;

    fn fixture_signers_xy() -> Vec<SignerXy> {
        let mut signers = Vec::new();
        for_each_set_bit(Bitmap::load(&SIGNERS_BITMAP), |i| {
            signers.push(PUBKEYS[i]);
            Ok::<(), AttestationError>(())
        })
        .unwrap();
        signers
    }

    /// Full member table: fixture keys in `[..REGISTERED_NODE_COUNT]`, zeroed after.
    fn fixture_nodes() -> Vec<NodeEntry> {
        let mut nodes = vec![NodeEntry::default(); MAX_REGISTRY_NODES];
        for (i, (x, y)) in PUBKEYS.iter().enumerate() {
            nodes[i] = NodeEntry {
                account: [i as u8; 32],
                x: *x,
                y: *y,
            };
        }
        nodes
    }

    fn fixture_registry(nodes: &[NodeEntry]) -> RegistryView<'_> {
        RegistryView {
            version: REGISTRY_VERSION,
            node_count: REGISTERED_NODE_COUNT as u16,
            redundancy_buffer: REDUNDANCY_BUFFER,
            nodes,
        }
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

    #[test]
    fn registry_accumulation_matches_ordered_signers() {
        let nodes = fixture_nodes();
        let registry = fixture_registry(&nodes);
        let coalition = accumulate_registry_signers(&registry, &SIGNERS_BITMAP).unwrap();
        assert_eq!(
            coalition.compressed_pubkey().unwrap(),
            reconstruct_coalition_key(&fixture_signers_xy()).unwrap()
        );
    }

    fn fixture_attestation() -> Attestation {
        Attestation {
            payload: crate::payload::AttestationPayload {
                value: VALUE,
                source_id: SOURCE_ID,
                registry_version: REGISTRY_VERSION,
                timestamp: TIMESTAMP,
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
        let nodes = fixture_nodes();
        verify(&fixture_attestation(), &fixture_registry(&nodes), None)
            .expect("fixture attestation must verify");
    }

    #[test]
    fn tampered_s_fails_verification() {
        let nodes = fixture_nodes();
        let mut attestation = fixture_attestation();
        attestation.signature.agg_sig_s[31] ^= 0x01;
        let res = verify(&attestation, &fixture_registry(&nodes), None);
        assert_eq!(res, Err(AttestationError::InvalidAggregateSignature));
    }

    #[test]
    fn wrong_registry_key_fails_verification() {
        let mut nodes = fixture_nodes();
        let first_signer = Bitmap::load(&SIGNERS_BITMAP).trailing_zeros();
        let other = (0..REGISTERED_NODE_COUNT as usize)
            .find(|i| !Bitmap::load(&SIGNERS_BITMAP).bit_set(*i))
            .unwrap();
        (nodes[first_signer].x, nodes[first_signer].y) = PUBKEYS[other];
        assert_eq!(
            verify(&fixture_attestation(), &fixture_registry(&nodes), None),
            Err(AttestationError::InvalidAggregateSignature)
        );
    }

    #[test]
    fn missing_member_table_is_rejected() {
        let registry = fixture_registry(&[]);
        assert_eq!(
            verify(&fixture_attestation(), &registry, None),
            Err(AttestationError::InvalidSignersBitmap)
        );
    }

    #[test]
    fn off_curve_registry_key_is_rejected() {
        let mut nodes = fixture_nodes();
        let first_signer = Bitmap::load(&SIGNERS_BITMAP).trailing_zeros();
        nodes[first_signer].y[31] ^= 0x01;
        assert!(verify(&fixture_attestation(), &fixture_registry(&nodes), None).is_err());
    }

    #[test]
    fn wrong_registry_version_is_rejected() {
        let nodes = fixture_nodes();
        let mut registry = fixture_registry(&nodes);
        registry.version = REGISTRY_VERSION + 1;
        assert_eq!(
            verify(&fixture_attestation(), &registry, None),
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
        let nodes = fixture_nodes();
        let key = coalition_key(&fixture_signers_xy()).unwrap();
        verify(
            &fixture_attestation(),
            &fixture_registry(&nodes),
            Some(&key),
        )
        .expect("keyed verification must accept the fixture");
    }

    #[test]
    fn verify_with_coalition_key_rejects_wrong_keys() {
        let nodes = fixture_nodes();
        let registry = fixture_registry(&nodes);
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
                verify(&attestation, &registry, Some(&bad)),
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
        let nodes = fixture_nodes();
        let mut attestation = fixture_attestation();
        attestation.signature.agg_sig_s[31] ^= 0x01;
        let key = coalition_key(&fixture_signers_xy()).unwrap();
        assert_eq!(
            verify(&attestation, &fixture_registry(&nodes), Some(&key)),
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
