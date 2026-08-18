//! Signer resolution and high-level verification over already-parsed registry data.
//!
//! These helpers are framework-agnostic: the caller is responsible for reading its registry
//! accounts (owner checks, deserialization) and passing the plain [`RegistryView`] and
//! [`NodeEntry`] slice. All Anchor / framework coupling stays in the downstream program.

use crate::verify::verify_attestation_parts;
use crate::{
    bitmap::{bitmap_load, for_each_set_bit_u256},
    secp256k1_scalar_is_valid_nonzero, verify_aggregate_over_hash, AttestationError,
    AttestationPayload, NodeEntry, RegistryTransitionType, RegistryView, SchnorrSignature,
    SignerXy, VIRTUAL_INDEX,
};

#[inline(always)]
pub fn expected_node_index(bit_pos: u32, registry: &RegistryView, apply_remove_remap: bool) -> u32 {
    if !apply_remove_remap {
        return bit_pos;
    }
    if bit_pos == registry.removed_old_index {
        VIRTUAL_INDEX
    } else if registry.last_transition_type == RegistryTransitionType::RemoveSwap
        && bit_pos == registry.moved_old_index
    {
        registry.removed_old_index
    } else {
        bit_pos
    }
}

#[inline(always)]
pub fn validate_remove_transition_for_previous(
    registry: &RegistryView,
) -> Result<(), AttestationError> {
    if registry.is_remove_transition() {
        Ok(())
    } else {
        Err(AttestationError::InvalidTransitionAccount)
    }
}

/// Pair each set bit of `signers_bitmap` with its registry entry (in `entries` order), validate the
/// node indices (applying remove-transition remapping for a live previous version), and return the
/// effective node count plus the signer pubkeys in ascending bitmap-bit order.
///
/// `entries` must contain exactly one entry per set bit, in the same order the caller iterated its
/// signer accounts, and each entry must already be owner-checked against the program.
pub fn resolve_ordered_signers(
    entries: &[NodeEntry],
    registry: &RegistryView,
    registry_version: u32,
    signers_bitmap: &[u8; 32],
    now: i64,
) -> Result<(u32, Vec<SignerXy>), AttestationError> {
    let signers = bitmap_load(signers_bitmap);
    let signer_count = signers.count_ones();

    let is_current = registry_version == registry.current_version;
    let is_previous_live =
        registry_version == registry.previous_version && now <= registry.previous_expires_at;
    if !is_current && !is_previous_live {
        return Err(AttestationError::InvalidRegistryVersion);
    }

    let node_count = if is_current {
        registry.current_node_count
    } else {
        registry.previous_node_count
    };

    if entries.len() != signer_count as usize {
        return Err(AttestationError::MissingSignerAccount);
    }

    let apply_remove_remap =
        !is_current && registry.last_transition_type != RegistryTransitionType::Add;
    if apply_remove_remap {
        validate_remove_transition_for_previous(registry)?;
    }

    let mut ordered = Vec::with_capacity(signer_count as usize);
    let mut entry_cursor = 0usize;
    for_each_set_bit_u256(signers, |bit_pos| {
        let bit_pos = bit_pos as u32;
        if bit_pos >= node_count {
            return Err(AttestationError::InvalidSignersBitmap);
        }

        let entry = entries
            .get(entry_cursor)
            .ok_or(AttestationError::MissingSignerAccount)?;
        entry_cursor = entry_cursor.saturating_add(1);

        let expected_index = expected_node_index(bit_pos, registry, apply_remove_remap);
        if entry.index != expected_index {
            return Err(AttestationError::InvalidNodeIndex);
        }
        ordered.push((entry.x, entry.y));
        Ok(())
    })?;

    if entry_cursor != entries.len() {
        return Err(AttestationError::MissingSignerAccount);
    }
    Ok((node_count, ordered))
}

#[allow(clippy::too_many_arguments)]
pub fn verify_attestation_resolved(
    payload: &AttestationPayload,
    signature: &SchnorrSignature,
    registry: &RegistryView,
    redundancy_buffer: u8,
    now: i64,
    entries: &[NodeEntry],
) -> Result<(), AttestationError> {
    let (node_count, ordered) = resolve_ordered_signers(
        entries,
        registry,
        payload.registry_version,
        &signature.signers_bitmap,
        now,
    )?;
    verify_attestation_parts(payload, signature, node_count, redundancy_buffer, &ordered)
}

#[allow(clippy::too_many_arguments)]
pub fn verify_aggregate_over_hash_resolved(
    registry: &RegistryView,
    registry_version: u32,
    signers_bitmap: &[u8; 32],
    agg_sig_s: &[u8; 32],
    commitment_addr: &[u8; 20],
    message_hash: &[u8; 32],
    now: i64,
    entries: &[NodeEntry],
) -> Result<bool, AttestationError> {
    if !secp256k1_scalar_is_valid_nonzero(agg_sig_s) {
        return Ok(false);
    }
    let (_, ordered) =
        resolve_ordered_signers(entries, registry, registry_version, signers_bitmap, now)?;
    verify_aggregate_over_hash(&ordered, agg_sig_s, commitment_addr, message_hash)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn remove_swap_registry() -> RegistryView {
        RegistryView {
            current_version: 2,
            previous_version: 1,
            previous_expires_at: 9_999,
            current_node_count: 7,
            previous_node_count: 8,
            last_transition_type: RegistryTransitionType::RemoveSwap,
            removed_old_index: 1,
            moved_old_index: 3,
        }
    }

    #[test]
    fn expected_node_index_remove_swap_remaps_removed_and_moved() {
        let registry = remove_swap_registry();
        assert_eq!(expected_node_index(1, &registry, true), VIRTUAL_INDEX);
        assert_eq!(expected_node_index(3, &registry, true), 1);
        assert_eq!(expected_node_index(0, &registry, true), 0);
    }

    #[test]
    fn expected_node_index_remove_tail_remaps_removed_only() {
        let mut registry = remove_swap_registry();
        registry.last_transition_type = RegistryTransitionType::RemoveTail;
        registry.removed_old_index = 2;
        registry.moved_old_index = VIRTUAL_INDEX;
        assert_eq!(expected_node_index(2, &registry, true), VIRTUAL_INDEX);
        assert_eq!(expected_node_index(0, &registry, true), 0);
    }

    #[test]
    fn expected_node_index_without_remove_remap_is_identity() {
        let registry = remove_swap_registry();
        assert_eq!(expected_node_index(4, &registry, false), 4);
    }

    #[test]
    fn resolve_ordered_signers_rejects_out_of_range_bit_on_add_previous() {
        let registry = RegistryView {
            current_version: 2,
            previous_version: 1,
            previous_expires_at: 9_999,
            current_node_count: 6,
            previous_node_count: 5,
            last_transition_type: RegistryTransitionType::Add,
            removed_old_index: VIRTUAL_INDEX,
            moved_old_index: VIRTUAL_INDEX,
        };
        let mut signers_bitmap = [0u8; 32];
        signers_bitmap[0] = 1 << 5;

        let entries = [NodeEntry {
            index: 5,
            x: [1u8; 32],
            y: [2u8; 32],
        }];

        let err = resolve_ordered_signers(
            &entries,
            &registry,
            registry.previous_version,
            &signers_bitmap,
            0,
        )
        .unwrap_err();
        assert_eq!(err, AttestationError::InvalidSignersBitmap);
    }
}
