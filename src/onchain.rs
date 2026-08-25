//! Signer resolution and high-level verification over already-parsed registry data.
//!
//! These helpers are framework-agnostic: the caller is responsible for reading its registry
//! accounts (owner checks, deserialization) and passing the plain [`RegistryView`] and
//! [`NodeEntry`] slice. All Anchor / framework coupling stays in the downstream program.
//!
//! Resolution binds each set bit of `signers_bitmap` to `registry.nodes[bit]` — the immutable
//! snapshot model. Node status is deliberately ignored: a node deactivated in a later version
//! remains valid evidence for historical snapshots.

use ethnum::U256;

use crate::verify::{verify_aggregate_over_hash_core, verify_attestation_core};
use crate::{
    bitmap::{bitmap_load, for_each_set_bit_u256},
    coalition::CoalitionAccumulator, Attestation, AttestationError, NodeEntry, RegistryView,
    SignerXy, SchnorrSignature,
};

/// Walk the set bits of `signers` in ascending order, bind each to its registry slot and the
/// entry supplied for it, and hand the validated pair to `visit`.
///
/// This is the whole of signer resolution. The public `resolve_*` helpers collect it into a
/// `Vec`; verification instead sums straight into the coalition accumulator, which is why the
/// binding checks live here rather than in the collecting wrappers.
fn for_each_resolved_signer<F>(
    nodes: &[[u8; 32]],
    node_count: u16,
    signers: U256,
    entries: &[NodeEntry],
    mut visit: F,
) -> Result<(), AttestationError>
where
    F: FnMut(usize, &NodeEntry) -> Result<(), AttestationError>,
{
    if entries.len() != signers.count_ones() as usize {
        return Err(AttestationError::MissingSignerAccount);
    }

    let mut cursor = 0usize;
    for_each_set_bit_u256(signers, |bit_pos| {
        if bit_pos >= usize::from(node_count) || bit_pos >= nodes.len() {
            return Err(AttestationError::InvalidSignersBitmap);
        }

        let entry = entries
            .get(cursor)
            .ok_or(AttestationError::MissingSignerAccount)?;
        cursor = cursor.saturating_add(1);

        if entry.account != nodes[bit_pos] {
            return Err(AttestationError::MissingSignerAccount);
        }
        visit(bit_pos, entry)
    })?;

    Ok(())
}

/// Resolve selected signer entries against an immutable registry snapshot.
///
/// Entries must be provided in ascending signer-bit order. Each entry's `account` must equal
/// `nodes[bit]` for the corresponding set bit.
pub fn resolve_registry_signers(
    nodes: &[[u8; 32]],
    node_count: u16,
    signers_bitmap: &[u8; 32],
    entries: &[NodeEntry],
) -> Result<Vec<SignerXy>, AttestationError> {
    let signers = bitmap_load(signers_bitmap);
    let mut ordered = Vec::with_capacity(signers.count_ones() as usize);
    for_each_resolved_signer(nodes, node_count, signers, entries, |_, entry| {
        ordered.push((entry.x, entry.y));
        Ok(())
    })?;
    Ok(ordered)
}

/// Like [`resolve_registry_signers`] but also returns each signer's bit position.
///
/// Used by callers that need to re-partition a resolved union bitmap back into per-statement
/// subsets — e.g. equivocation punishment, which resolves the union of two signer sets once and
/// then splits the result back into each statement's ordered signers.
pub fn resolve_registry_signers_indexed(
    nodes: &[[u8; 32]],
    node_count: u16,
    signers_bitmap: &[u8; 32],
    entries: &[NodeEntry],
) -> Result<Vec<(usize, SignerXy)>, AttestationError> {
    let signers = bitmap_load(signers_bitmap);
    let mut ordered = Vec::with_capacity(signers.count_ones() as usize);
    for_each_resolved_signer(nodes, node_count, signers, entries, |bit_pos, entry| {
        ordered.push((bit_pos, (entry.x, entry.y)));
        Ok(())
    })?;
    Ok(ordered)
}

/// Verify an attestation after resolving signers against a registry snapshot.
pub fn verify_attestation_resolved(
    attestation: &Attestation,
    registry: &RegistryView<'_>,
    entries: &[NodeEntry],
) -> Result<(), AttestationError> {
    if attestation.payload.registry_version != registry.version {
        return Err(AttestationError::InvalidRegistryVersion);
    }

    let signers = bitmap_load(&attestation.signature.signers_bitmap);
    if entries.len() != signers.count_ones() as usize {
        return Err(AttestationError::MissingSignerAccount);
    }

    verify_attestation_core(
        attestation,
        u32::from(registry.node_count),
        registry.redundancy_buffer,
        entries.len(),
        |coalition| {
            accumulate_resolved_signers(
                registry.nodes,
                registry.node_count,
                signers,
                entries,
                coalition,
            )
        },
    )
}

/// Verify an aggregate signature over an arbitrary message hash after resolving signers.
///
/// Returns `Ok(true)` when valid, `Ok(false)` when invalid (slashable), `Err` on malformed input.
pub fn verify_aggregate_over_hash_resolved(
    registry: &RegistryView<'_>,
    signature: &SchnorrSignature,
    message_hash: &[u8; 32],
    entries: &[NodeEntry],
) -> Result<bool, AttestationError> {
    let signers = bitmap_load(&signature.signers_bitmap);
    verify_aggregate_over_hash_core(
        &signature.agg_sig_s,
        &signature.commitment_addr,
        message_hash,
        entries.len(),
        |coalition| {
            accumulate_resolved_signers(
                registry.nodes,
                registry.node_count,
                signers,
                entries,
                coalition,
            )
        },
    )
}

fn accumulate_resolved_signers(
    nodes: &[[u8; 32]],
    node_count: u16,
    signers: U256,
    entries: &[NodeEntry],
    coalition: &mut CoalitionAccumulator,
) -> Result<(), AttestationError> {
    for_each_resolved_signer(nodes, node_count, signers, entries, |_, entry| {
        coalition.add_stored_xy(&entry.x, &entry.y)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bitmap::{bitmap_set_bit, for_each_set_bit};
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
                commitment_addr: COMMITMENT,
                signers_bitmap: SIGNERS_BITMAP,
            },
        }
    }

    fn fixture_entries(nodes: &[[u8; 32]; MAX_REGISTRY_NODES]) -> Vec<NodeEntry> {
        let mut entries = Vec::new();
        for_each_set_bit(&SIGNERS_BITMAP, |bit_pos| {
            let (x, y) = PUBKEYS[bit_pos];
            entries.push(NodeEntry {
                account: nodes[bit_pos],
                x,
                y,
            });
        });
        entries
    }

    #[test]
    fn resolve_registry_signers_accepts_evm_fixture() {
        let nodes = fixture_nodes();
        let entries = fixture_entries(&nodes);
        let ordered = resolve_registry_signers(
            &nodes,
            REGISTERED_NODE_COUNT as u16,
            &SIGNERS_BITMAP,
            &entries,
        )
        .expect("fixture must resolve");
        assert_eq!(ordered.len(), entries.len());
    }

    #[test]
    fn resolve_registry_signers_indexed_returns_ascending_bits() {
        let nodes = fixture_nodes();
        let entries = fixture_entries(&nodes);
        let indexed = resolve_registry_signers_indexed(
            &nodes,
            REGISTERED_NODE_COUNT as u16,
            &SIGNERS_BITMAP,
            &entries,
        )
        .expect("fixture must resolve");

        let mut expected_bits = Vec::new();
        for_each_set_bit(&SIGNERS_BITMAP, |bit| expected_bits.push(bit));
        let got_bits: Vec<usize> = indexed.iter().map(|(b, _)| *b).collect();
        assert_eq!(got_bits, expected_bits);
    }

    #[test]
    fn resolve_rejects_out_of_range_bit() {
        let mut nodes = [[0u8; 32]; 4];
        nodes[0] = [1u8; 32];
        let mut signers_bitmap = [0u8; 32];
        bitmap_set_bit(&mut signers_bitmap, 5); // >= node_count

        let entries = [NodeEntry {
            account: [1u8; 32],
            x: [2u8; 32],
            y: [3u8; 32],
        }];

        let err = resolve_registry_signers(&nodes, 4, &signers_bitmap, &entries).unwrap_err();
        assert_eq!(err, AttestationError::InvalidSignersBitmap);
    }

    #[test]
    fn resolve_rejects_wrong_account() {
        let nodes = fixture_nodes();
        let mut entries = fixture_entries(&nodes);
        entries[0].account = [0xff; 32];

        let err = resolve_registry_signers(
            &nodes,
            REGISTERED_NODE_COUNT as u16,
            &SIGNERS_BITMAP,
            &entries,
        )
        .unwrap_err();
        assert_eq!(err, AttestationError::MissingSignerAccount);
    }

    #[test]
    fn resolve_rejects_missing_or_extra_entries() {
        let nodes = fixture_nodes();
        let entries = fixture_entries(&nodes);

        let err = resolve_registry_signers(
            &nodes,
            REGISTERED_NODE_COUNT as u16,
            &SIGNERS_BITMAP,
            &entries[..entries.len() - 1],
        )
        .unwrap_err();
        assert_eq!(err, AttestationError::MissingSignerAccount);

        let mut extra = entries.clone();
        extra.push(NodeEntry {
            account: [0u8; 32],
            x: [0u8; 32],
            y: [0u8; 32],
        });
        let err = resolve_registry_signers(
            &nodes,
            REGISTERED_NODE_COUNT as u16,
            &SIGNERS_BITMAP,
            &extra,
        )
        .unwrap_err();
        assert_eq!(err, AttestationError::MissingSignerAccount);
    }

    #[test]
    fn verify_attestation_resolved_accepts_fixture() {
        let nodes = fixture_nodes();
        let registry = fixture_registry(&nodes);
        let attestation = fixture_attestation();
        let entries = fixture_entries(&nodes);
        verify_attestation_resolved(&attestation, &registry, &entries)
            .expect("resolved-path fixture must verify");
    }

    #[test]
    fn verify_attestation_resolved_rejects_version_mismatch() {
        let nodes = fixture_nodes();
        let mut registry = fixture_registry(&nodes);
        registry.version = REGISTRY_VERSION + 1;
        let attestation = fixture_attestation();
        let entries = fixture_entries(&nodes);
        let err = verify_attestation_resolved(&attestation, &registry, &entries).unwrap_err();
        assert_eq!(err, AttestationError::InvalidRegistryVersion);
    }
}
