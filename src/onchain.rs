//! Signer resolution and verification over an already-parsed registry snapshot.
//!
//! Framework-agnostic: the caller reads the registry account and passes a [`RegistryView`]. Each
//! set bit of a signers bitmap binds to `registry.nodes[bit]`, and its key comes from that
//! member record. Node status is not part of the snapshot — a node deactivated later remains
//! valid evidence for historical snapshots.

use crate::verify::{accumulate_registry_signers, compress_coalition, recover_and_match};
use crate::{
    bitmap::{for_each_set_bit, Bitmap},
    scalar::secp256k1_scalar_is_valid_nonzero,
    AttestationError, CoalitionKey, RegistryView, SchnorrSignature, SignerXy,
};

/// Registry keys for the set bits of `signers_bitmap`, in ascending bit order.
///
/// Off-chain helper, e.g. to compute a [`CoalitionKey`] with [`crate::coalition_key`].
/// Verification reads the registry directly and does not need it.
pub fn resolve_signers(
    registry: &RegistryView<'_>,
    signers_bitmap: &[u8; 32],
) -> Result<Vec<SignerXy>, AttestationError> {
    let signers = Bitmap::load(signers_bitmap);
    let mut ordered = Vec::with_capacity(signers.popcount() as usize);
    for_each_set_bit(signers, |bit| {
        ordered.push(registry.signer(bit)?.xy());
        Ok(())
    })?;
    Ok(ordered)
}

/// Verify an aggregate over an arbitrary message hash, with signer keys from `registry`.
///
/// `Ok(true)` = valid, `Ok(false)` = invalid (slashable), `Err` = malformed input: an empty
/// bitmap, a bit outside the registry, an invalid registry key, or a wrong `coalition_key`.
/// Signers are resolved before the scalar check, so bad input never yields a verdict.
pub fn verify_aggregate_over_hash_resolved(
    registry: &RegistryView<'_>,
    signature: &SchnorrSignature,
    message_hash: &[u8; 32],
    coalition_key: Option<&CoalitionKey>,
) -> Result<bool, AttestationError> {
    let coalition = accumulate_registry_signers(registry, &signature.signers_bitmap)?;
    if !secp256k1_scalar_is_valid_nonzero(&signature.agg_sig_s) {
        return Ok(false);
    }
    let x_coalition = compress_coalition(&coalition, coalition_key)?;
    Ok(recover_and_match(
        &x_coalition,
        message_hash,
        &signature.agg_sig_s,
        &signature.commitment,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixtures::{
        COMMITMENT, PUBKEYS, REDUNDANCY_BUFFER, REGISTERED_NODE_COUNT, REGISTRY_VERSION, S,
        SIGNATURES_REQUIRED, SIGNERS_BITMAP, SOURCE_ID, TIMESTAMP, VALUE,
    };
    use crate::{Attestation, NodeEntry, MAX_REGISTRY_NODES};

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

    fn fixture_attestation() -> Attestation {
        Attestation {
            payload: crate::payload::AttestationPayload {
                value: VALUE,
                source_id: SOURCE_ID,
                registry_version: REGISTRY_VERSION,
                timestamp: TIMESTAMP,
                signatures_required: SIGNATURES_REQUIRED,
            },
            signature: SchnorrSignature {
                agg_sig_s: S,
                commitment: COMMITMENT,
                signers_bitmap: SIGNERS_BITMAP,
            },
        }
    }

    #[test]
    fn resolve_signers_reads_keys_in_bit_order() {
        let nodes = fixture_nodes();
        let ordered = resolve_signers(&fixture_registry(&nodes), &SIGNERS_BITMAP).unwrap();
        let mut expected = Vec::new();
        for_each_set_bit(Bitmap::load(&SIGNERS_BITMAP), |bit| {
            expected.push(PUBKEYS[bit]);
            Ok::<(), AttestationError>(())
        })
        .unwrap();
        assert_eq!(ordered, expected);
    }

    #[test]
    fn resolve_rejects_out_of_range_bit() {
        let nodes = fixture_nodes();
        let registry = RegistryView {
            node_count: 4,
            ..fixture_registry(&nodes)
        };
        let mut bm = Bitmap::EMPTY;
        bm.set_bit(5);
        assert_eq!(
            resolve_signers(&registry, &bm.to_bytes()).unwrap_err(),
            AttestationError::InvalidSignersBitmap
        );
    }

    #[test]
    fn resolve_rejects_bit_beyond_member_table() {
        let nodes = [NodeEntry::default(); 1];
        let registry = RegistryView {
            version: 0,
            node_count: 4,
            redundancy_buffer: 0,
            nodes: &nodes,
        };
        let mut bm = Bitmap::EMPTY;
        bm.set_bit(2);
        assert_eq!(
            resolve_signers(&registry, &bm.to_bytes()).unwrap_err(),
            AttestationError::InvalidSignersBitmap
        );
    }

    #[test]
    fn aggregate_over_hash_resolved_roundtrip() {
        let nodes = fixture_nodes();
        let registry = fixture_registry(&nodes);
        let attestation = fixture_attestation();
        let message_hash = attestation.message_hash();
        let signature = &attestation.signature;

        assert_eq!(
            verify_aggregate_over_hash_resolved(&registry, signature, &message_hash, None),
            Ok(true)
        );

        let mut bad_hash = message_hash;
        bad_hash[0] ^= 0xff;
        assert_eq!(
            verify_aggregate_over_hash_resolved(&registry, signature, &bad_hash, None),
            Ok(false)
        );
    }

    #[test]
    fn aggregate_over_hash_resolved_checks_the_coalition_key() {
        let nodes = fixture_nodes();
        let registry = fixture_registry(&nodes);
        let attestation = fixture_attestation();
        let message_hash = attestation.message_hash();
        let signers = resolve_signers(&registry, &SIGNERS_BITMAP).unwrap();
        let key = crate::coalition_key(&signers).unwrap();

        assert_eq!(
            verify_aggregate_over_hash_resolved(
                &registry,
                &attestation.signature,
                &message_hash,
                Some(&key)
            ),
            Ok(true)
        );

        let mut bad = key;
        bad.x[0] ^= 0x01;
        assert_eq!(
            verify_aggregate_over_hash_resolved(
                &registry,
                &attestation.signature,
                &message_hash,
                Some(&bad)
            ),
            Err(AttestationError::InvalidCoalitionKey)
        );
    }

    #[test]
    fn invalid_scalar_is_a_verdict_but_bad_bitmap_is_an_error() {
        let nodes = fixture_nodes();
        let registry = fixture_registry(&nodes);
        let attestation = fixture_attestation();
        let message_hash = attestation.message_hash();

        let mut signature = attestation.signature.clone();
        signature.agg_sig_s = [0xff; 32];
        assert_eq!(
            verify_aggregate_over_hash_resolved(&registry, &signature, &message_hash, None),
            Ok(false)
        );

        // A bit outside the registry must error even with an invalid scalar: no slashable
        // verdict on malformed input.
        let mut out_of_range = Bitmap::load(&signature.signers_bitmap);
        out_of_range.set_bit(REGISTERED_NODE_COUNT as usize);
        signature.signers_bitmap = out_of_range.to_bytes();
        assert_eq!(
            verify_aggregate_over_hash_resolved(&registry, &signature, &message_hash, None),
            Err(AttestationError::InvalidSignersBitmap)
        );

        signature.signers_bitmap = [0u8; 32];
        assert_eq!(
            verify_aggregate_over_hash_resolved(&registry, &signature, &message_hash, None),
            Err(AttestationError::InvalidSignersBitmap)
        );
    }
}
