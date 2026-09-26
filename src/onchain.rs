//! Signer resolution and verification over already-parsed registry data.
//!
//! Framework-agnostic: the caller reads accounts and passes [`RegistryView`] + [`NodeEntry`]s.
//! Each set bit of `signers_bitmap` binds to `registry.nodes[bit]`. Node status is ignored —
//! a node deactivated later remains valid evidence for historical snapshots.

use crate::verify::{
    verify, verify_aggregate_over_hash, verify_aggregate_over_hash_with_coalition_key,
    verify_with_coalition_key,
};
use crate::{
    bitmap::{for_each_set_bit, Bitmap},
    Attestation, AttestationError, CoalitionKey, NodeEntry, RegistryView, SchnorrSignature,
    SignerXy,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IntersectedResolution {
    pub signers_a: Vec<SignerXy>,
    pub signers_b: Vec<SignerXy>,
    pub intersected_bitmap: Bitmap,
    pub unioned_bitmap: Bitmap,
}

pub fn resolve_signers(
    nodes: &[NodeEntry],
    registry: &RegistryView<'_>,
    signers_bitmap: &[u8; 32],
) -> Result<Vec<SignerXy>, AttestationError> {
    let signers = Bitmap::load(signers_bitmap);
    let mut ordered = Vec::with_capacity(signers.popcount() as usize);

    if nodes.len() != signers.popcount() as usize {
        return Err(AttestationError::MissingSignerAccount);
    }

    let mut cursor = 0usize;
    for_each_set_bit(signers, |bit_pos| {
        if bit_pos >= registry.node_count as usize || bit_pos >= registry.nodes.len() {
            return Err(AttestationError::InvalidSignersBitmap);
        }

        let entry = nodes
            .get(cursor)
            .ok_or(AttestationError::MissingSignerAccount)?;
        if entry.account != registry.nodes[bit_pos] {
            return Err(AttestationError::MissingSignerAccount);
        }

        cursor = cursor.saturating_add(1);
        ordered.push((entry.x, entry.y));
        Ok(())
    })?;

    Ok(ordered)
}

pub fn resolve_intersected_signers(
    nodes: &[NodeEntry],
    registry: &RegistryView,
    bitmap_a: &[u8; 32],
    bitmap_b: &[u8; 32],
) -> Result<IntersectedResolution, AttestationError> {
    let signers_a = Bitmap::load(bitmap_a);
    let signers_b = Bitmap::load(bitmap_b);
    let intersected = signers_a.intersect(&signers_b);
    let unioned = signers_a.union(&signers_b);

    if nodes.len() != unioned.popcount() as usize {
        return Err(AttestationError::MissingSignerAccount);
    }

    let mut cursor = 0usize;
    let mut ordered_a = Vec::with_capacity(intersected.popcount() as usize);
    let mut ordered_b = Vec::with_capacity(intersected.popcount() as usize);

    for_each_set_bit(unioned, |bit_pos| {
        if bit_pos >= registry.node_count as usize || bit_pos >= registry.nodes.len() {
            return Err(AttestationError::InvalidSignersBitmap);
        }

        let entry = nodes
            .get(cursor)
            .ok_or(AttestationError::MissingSignerAccount)?;
        if entry.account != registry.nodes[bit_pos] {
            return Err(AttestationError::MissingSignerAccount);
        }

        cursor = cursor.saturating_add(1);

        if signers_a.bit_set(bit_pos) {
            ordered_a.push((entry.x, entry.y));
        }
        if signers_b.bit_set(bit_pos) {
            ordered_b.push((entry.x, entry.y));
        }

        Ok(())
    })?;

    let resolution = IntersectedResolution {
        signers_a: ordered_a,
        signers_b: ordered_b,
        intersected_bitmap: intersected,
        unioned_bitmap: unioned,
    };

    Ok(resolution)
}

/// Verify an attestation after resolving signers against a registry snapshot.
pub fn verify_attestation_resolved(
    attestation: &Attestation,
    registry: &RegistryView<'_>,
    nodes: &[NodeEntry],
) -> Result<(), AttestationError> {
    if attestation.payload.registry_version != registry.version {
        return Err(AttestationError::InvalidRegistryVersion);
    }

    let ordered_signers = resolve_signers(nodes, registry, &attestation.signature.signers_bitmap)?;

    verify(attestation, &ordered_signers, registry)
}

/// [`verify_attestation_resolved`] with the affine coalition key supplied (see
/// [`crate::verify_with_coalition_key`]).
pub fn verify_attestation_resolved_with_coalition_key(
    attestation: &Attestation,
    registry: &RegistryView<'_>,
    nodes: &[NodeEntry],
    coalition_key: &CoalitionKey,
) -> Result<(), AttestationError> {
    if attestation.payload.registry_version != registry.version {
        return Err(AttestationError::InvalidRegistryVersion);
    }

    let ordered_signers = resolve_signers(nodes, registry, &attestation.signature.signers_bitmap)?;

    verify_with_coalition_key(attestation, &ordered_signers, registry, coalition_key)
}

/// Verify an aggregate over an arbitrary message hash after resolving signers.
///
/// `Ok(true)` = valid, `Ok(false)` = invalid (slashable), `Err` = malformed input.
pub fn verify_aggregate_over_hash_resolved(
    registry: &RegistryView<'_>,
    signature: &SchnorrSignature,
    message_hash: &[u8; 32],
    nodes: &[NodeEntry],
) -> Result<bool, AttestationError> {
    let ordered_signers = resolve_signers(nodes, registry, &signature.signers_bitmap)?;
    verify_aggregate_over_hash(
        &signature.agg_sig_s,
        &signature.commitment,
        message_hash,
        &ordered_signers,
    )
}

/// [`verify_aggregate_over_hash_resolved`] with the affine coalition key supplied (see
/// [`crate::verify_aggregate_over_hash_with_coalition_key`]).
pub fn verify_aggregate_over_hash_resolved_with_coalition_key(
    registry: &RegistryView<'_>,
    signature: &SchnorrSignature,
    message_hash: &[u8; 32],
    nodes: &[NodeEntry],
    coalition_key: &CoalitionKey,
) -> Result<bool, AttestationError> {
    let ordered_signers = resolve_signers(nodes, registry, &signature.signers_bitmap)?;
    verify_aggregate_over_hash_with_coalition_key(
        &signature.agg_sig_s,
        &signature.commitment,
        message_hash,
        &ordered_signers,
        coalition_key,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bitmap::{for_each_set_bit, Bitmap};
    use crate::fixtures::{
        CANONICAL_TIMESTAMP, COMMITMENT, PUBKEYS, REDUNDANCY_BUFFER, REGISTERED_NODE_COUNT,
        REGISTRY_VERSION, S, SIGNATURES_REQUIRED, SIGNERS_BITMAP, SOURCE_ID, VALUE,
    };
    use crate::MAX_REGISTRY_NODES;

    fn fixture_nodes() -> [[u8; 32]; MAX_REGISTRY_NODES] {
        let mut nodes = [[0u8; 32]; MAX_REGISTRY_NODES];
        for (i, node) in nodes
            .iter_mut()
            .enumerate()
            .take(REGISTERED_NODE_COUNT as usize)
        {
            *node = [i as u8; 32];
        }
        nodes
    }

    fn fixture_registry(nodes: &[[u8; 32]; MAX_REGISTRY_NODES]) -> RegistryView<'_> {
        RegistryView {
            version: REGISTRY_VERSION,
            node_count: REGISTERED_NODE_COUNT as u16,
            redundancy_buffer: REDUNDANCY_BUFFER,
            nodes: &nodes[..],
        }
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

    fn fixture_entries(nodes: &[[u8; 32]; MAX_REGISTRY_NODES]) -> Vec<NodeEntry> {
        let mut entries = Vec::new();
        for_each_set_bit(Bitmap::load(&SIGNERS_BITMAP), |bit_pos| {
            let (x, y) = PUBKEYS[bit_pos];
            entries.push(NodeEntry {
                account: nodes[bit_pos],
                x,
                y,
            });
            Ok::<(), AttestationError>(())
        })
        .unwrap();
        entries
    }

    #[test]
    fn resolve_signers_accepts_evm_fixture() {
        let nodes_array = fixture_nodes();
        let registry = fixture_registry(&nodes_array);
        let entries = fixture_entries(&nodes_array);
        let ordered =
            resolve_signers(&entries, &registry, &SIGNERS_BITMAP).expect("fixture must resolve");
        assert_eq!(ordered.len(), entries.len());
    }

    #[test]
    fn resolve_rejects_out_of_range_bit() {
        let mut nodes_array = [[0u8; 32]; MAX_REGISTRY_NODES];
        nodes_array[0] = [1u8; 32];
        let registry = RegistryView {
            version: 0,
            node_count: 4,
            redundancy_buffer: 0,
            nodes: &nodes_array[..],
        };
        let mut bm = Bitmap::EMPTY;
        bm.set_bit(5);
        let signers_bitmap = bm.to_bytes();

        let entries = [NodeEntry {
            account: [1u8; 32],
            x: [2u8; 32],
            y: [3u8; 32],
        }];

        let err = resolve_signers(&entries, &registry, &signers_bitmap).unwrap_err();
        assert_eq!(err, AttestationError::InvalidSignersBitmap);
    }

    #[test]
    fn resolve_rejects_bit_beyond_supplied_nodes_slice() {
        let nodes_array = [[1u8; 32]; 1];
        let registry = RegistryView {
            version: 0,
            node_count: 4,
            redundancy_buffer: 0,
            nodes: &nodes_array,
        };
        let mut bm = Bitmap::EMPTY;
        bm.set_bit(2);
        let signers_bitmap = bm.to_bytes();

        let entries = [NodeEntry {
            account: [1u8; 32],
            x: [2u8; 32],
            y: [3u8; 32],
        }];

        let err = resolve_signers(&entries, &registry, &signers_bitmap).unwrap_err();
        assert_eq!(err, AttestationError::InvalidSignersBitmap);

        let err =
            resolve_intersected_signers(&entries, &registry, &signers_bitmap, &signers_bitmap)
                .unwrap_err();
        assert_eq!(err, AttestationError::InvalidSignersBitmap);
    }

    #[test]
    fn resolve_rejects_wrong_account() {
        let nodes_array = fixture_nodes();
        let registry = fixture_registry(&nodes_array);
        let mut entries = fixture_entries(&nodes_array);
        entries[0].account = [0xff; 32];

        let err = resolve_signers(&entries, &registry, &SIGNERS_BITMAP).unwrap_err();
        assert_eq!(err, AttestationError::MissingSignerAccount);
    }

    #[test]
    fn resolve_rejects_missing_or_extra_entries() {
        let nodes_array = fixture_nodes();
        let registry = fixture_registry(&nodes_array);
        let entries = fixture_entries(&nodes_array);

        let err =
            resolve_signers(&entries[..entries.len() - 1], &registry, &SIGNERS_BITMAP).unwrap_err();
        assert_eq!(err, AttestationError::MissingSignerAccount);

        let mut extra = entries.clone();
        extra.push(NodeEntry {
            account: [0u8; 32],
            x: [0u8; 32],
            y: [0u8; 32],
        });
        let err = resolve_signers(&extra, &registry, &SIGNERS_BITMAP).unwrap_err();
        assert_eq!(err, AttestationError::MissingSignerAccount);
    }

    #[test]
    fn verify_attestation_resolved_accepts_fixture() {
        let nodes_array = fixture_nodes();
        let registry = fixture_registry(&nodes_array);
        let attestation = fixture_attestation();
        let entries = fixture_entries(&nodes_array);
        verify_attestation_resolved(&attestation, &registry, &entries)
            .expect("resolved-path fixture must verify");
    }

    #[test]
    fn verify_resolved_with_coalition_key_accepts_fixture_and_rejects_bad_key() {
        let nodes_array = fixture_nodes();
        let registry = fixture_registry(&nodes_array);
        let attestation = fixture_attestation();
        let entries = fixture_entries(&nodes_array);
        let signers = resolve_signers(&entries, &registry, &SIGNERS_BITMAP).unwrap();
        let key = crate::coalition_key(&signers).unwrap();
        verify_attestation_resolved_with_coalition_key(&attestation, &registry, &entries, &key)
            .expect("keyed resolved path must verify");
        assert!(verify_aggregate_over_hash_resolved_with_coalition_key(
            &registry,
            &attestation.signature,
            &attestation.message_hash(),
            &entries,
            &key,
        )
        .unwrap());

        let mut bad = key;
        bad.x[0] ^= 0x01;
        assert_eq!(
            verify_attestation_resolved_with_coalition_key(&attestation, &registry, &entries, &bad),
            Err(AttestationError::InvalidCoalitionKey)
        );
        assert_eq!(
            verify_aggregate_over_hash_resolved_with_coalition_key(
                &registry,
                &attestation.signature,
                &attestation.message_hash(),
                &entries,
                &bad,
            ),
            Err(AttestationError::InvalidCoalitionKey)
        );
    }

    #[test]
    fn verify_attestation_resolved_rejects_version_mismatch() {
        let nodes_array = fixture_nodes();
        let mut registry = fixture_registry(&nodes_array);
        registry.version = REGISTRY_VERSION + 1;
        let attestation = fixture_attestation();
        let entries = fixture_entries(&nodes_array);
        let err = verify_attestation_resolved(&attestation, &registry, &entries).unwrap_err();
        assert_eq!(err, AttestationError::InvalidRegistryVersion);
    }
}
