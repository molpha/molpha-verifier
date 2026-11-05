//! Framework-agnostic registry snapshot view.
//!
//! Canonical account types live in the downstream program. Callers pass a [`RegistryView`] whose
//! `nodes` carry each member's account address and secp256k1 key, so signers are resolved from
//! the snapshot itself.
//!
//! # Records and bits
//!
//! The 256-bit signers bitmap splits in two, frozen by the protocol: bits `[0, NODE_SLOTS)` are
//! operator nodes (node slot `i` at bit `i`), bits `[NODE_SLOTS, 256)` are provider signers
//! (provider slot `p` at bit `NODE_SLOTS + p`). A snapshot stores the two segments as two compact
//! tables, nodes then providers, so a provider costs no padding up to bit 64:
//! [`RegistryView::signer`] maps a bit to its record. A set bit of either segment must name a live
//! record. Every set bit counts toward the quorum (at most one of them a provider bit); only node
//! bits take part in committee selection.

use crate::error::AttestationError;

/// Maximum registry records (signer bitmaps are 256-bit): node slots and provider slots together.
pub const MAX_REGISTRY_NODES: usize = 256;

/// Bits `[0, NODE_SLOTS)` belong to operator nodes, node slot `i` at bit `i`.
pub const NODE_SLOTS: usize = 64;

/// Bit of provider slot 0; provider slot `p` signs at bit `PROVIDER_BIT_BASE + p`.
pub const PROVIDER_BIT_BASE: usize = NODE_SLOTS;

/// Provider slots (`p` in `0..MAX_PROVIDER_SLOTS`, at bits `64..256`).
pub const MAX_PROVIDER_SLOTS: usize = MAX_REGISTRY_NODES - NODE_SLOTS;

/// Secp256k1 affine coordinates `(x, y)`, big-endian.
pub type SignerXy = ([u8; 32], [u8; 32]);

/// Immutable, version-addressed registry snapshot.
///
/// A member keeps its slot (its signer bit) for as long as it is in the snapshot: removing a
/// member leaves a vacant slot instead of moving the last member into it. Each segment counts its
/// slots **holes included**: `node_count` is the highest live node slot + 1 (at most
/// [`NODE_SLOTS`] on chain), `provider_count` the highest live provider slot + 1. The count of live
/// **node** members is [`RegistryView::live_count`]. A hole is an all-zero [`NodeEntry`]; trailing
/// holes are never stored, so the last record of each segment is live.
///
/// `nodes` and `providers` are borrowed so on-chain callers can view the account's tables without
/// copying (see [`NodeEntry::slice_from_bytes`]). Selection-only callers may pass `&[]` for both,
/// which reads as a registry without holes; verification then fails with
/// [`AttestationError::InvalidSignersBitmap`].
#[derive(Clone, Copy, Debug)]
pub struct RegistryView<'a> {
    pub version: u32,
    /// Node slots, holes included. Selection reads at most [`NODE_SLOTS`] of them.
    pub node_count: u16,
    /// Provider slots, holes included: provider slot `p` (bit `PROVIDER_BIT_BASE + p`) for
    /// `p < provider_count`.
    pub provider_count: u16,
    pub redundancy_buffer: u8,
    /// Node slots in order; only `nodes[..node_count]` is populated.
    pub nodes: &'a [NodeEntry],
    /// Provider slots in order; only `providers[..provider_count]` is populated.
    pub providers: &'a [NodeEntry],
}

impl RegistryView<'_> {
    /// The member bound to signer bit `bit`: node slot `bit` when `bit < NODE_SLOTS`, else
    /// provider slot `bit - PROVIDER_BIT_BASE`.
    ///
    /// Errors unless the slot is below its segment's count, its table covers it and it is live. A
    /// hole is refused in both segments.
    #[inline(always)]
    pub fn signer(&self, bit: usize) -> Result<&NodeEntry, AttestationError> {
        let (table, slot, count) = if bit < NODE_SLOTS {
            (self.nodes, bit, self.node_count)
        } else {
            (self.providers, bit - PROVIDER_BIT_BASE, self.provider_count)
        };
        if slot >= usize::from(count) {
            return Err(AttestationError::InvalidSignersBitmap);
        }
        match table.get(slot) {
            Some(member) if !member.is_vacant() => Ok(member),
            _ => Err(AttestationError::InvalidSignersBitmap),
        }
    }

    /// The live **node** slots (`< NODE_SLOTS`) in ascending order. Providers are not nodes: they
    /// are never selected and never counted toward the committee.
    ///
    /// Without a member table (`nodes` shorter than the slots examined, for example the empty
    /// slice of a selection-only caller) every node slot below `node_count` is taken to be live.
    pub fn live_slots(&self) -> LiveSlots {
        let slots = usize::from(self.node_count).min(NODE_SLOTS);
        let mut out = LiveSlots {
            slots: [0; NODE_SLOTS],
            len: 0,
        };
        let table = self.nodes.get(..slots);
        for slot in 0..slots {
            if table.is_none_or(|nodes| !nodes[slot].is_vacant()) {
                out.slots[out.len] = slot as u16;
                out.len += 1;
            }
        }
        out
    }

    /// Number of live node members (node slots minus the holes). Providers are not counted.
    pub fn live_count(&self) -> u32 {
        self.live_slots().len() as u32
    }
}

/// The live node slots of a snapshot in ascending order, as returned by
/// [`RegistryView::live_slots`].
#[derive(Clone, Copy, Debug)]
pub struct LiveSlots {
    slots: [u16; NODE_SLOTS],
    len: usize,
}

impl LiveSlots {
    /// Number of live slots.
    #[inline(always)]
    pub fn len(&self) -> usize {
        self.len
    }

    #[inline(always)]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// The slot of the `rank`-th live member (0-based), or `None` past the last.
    #[inline(always)]
    pub fn slot(&self, rank: usize) -> Option<usize> {
        self.as_slice().get(rank).map(|slot| usize::from(*slot))
    }

    /// The live slots as a slice, ascending.
    #[inline(always)]
    pub fn as_slice(&self) -> &[u16] {
        &self.slots[..self.len]
    }
}

/// One registry member: account pubkey plus secp256k1 affine coordinates (big-endian).
///
/// `repr(C)` with byte-array fields only: 96 bytes, alignment 1, laid out exactly like the
/// program's registry member record, so account data can be reinterpreted in place.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct NodeEntry {
    pub account: [u8; 32],
    pub x: [u8; 32],
    pub y: [u8; 32],
}

const _: () = assert!(core::mem::size_of::<NodeEntry>() == NodeEntry::LEN);
const _: () = assert!(core::mem::align_of::<NodeEntry>() == 1);

impl NodeEntry {
    /// Serialized record length.
    pub const LEN: usize = 96;

    #[inline(always)]
    pub fn xy(&self) -> SignerXy {
        (self.x, self.y)
    }

    /// A hole: the slot of a removed member. Live members always carry a non-zero account.
    #[inline(always)]
    pub fn is_vacant(&self) -> bool {
        // Four word reads: a byte-wise compare of 32 bytes costs far more on SBF.
        let a = &self.account;
        let word = |i: usize| {
            u64::from_ne_bytes([
                a[i],
                a[i + 1],
                a[i + 2],
                a[i + 3],
                a[i + 4],
                a[i + 5],
                a[i + 6],
                a[i + 7],
            ])
        };
        (word(0) | word(8) | word(16) | word(24)) == 0
    }

    /// View packed 96-byte records as entries without copying.
    ///
    /// `None` unless `bytes.len()` is a whole number of records.
    pub fn slice_from_bytes(bytes: &[u8]) -> Option<&[NodeEntry]> {
        if !bytes.len().is_multiple_of(Self::LEN) {
            return None;
        }
        // SAFETY: `NodeEntry` is `repr(C)` over `[u8; 32]` fields only, so it has size `LEN`,
        // alignment 1, no padding, and every bit pattern is valid. `bytes` holds exactly
        // `len / LEN` records, and the returned slice borrows `bytes`.
        Some(unsafe {
            core::slice::from_raw_parts(bytes.as_ptr().cast::<NodeEntry>(), bytes.len() / Self::LEN)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slice_from_bytes_reads_records_in_place() {
        let mut bytes = [0u8; 2 * NodeEntry::LEN];
        for (i, byte) in bytes.iter_mut().enumerate() {
            *byte = i as u8;
        }
        let entries = NodeEntry::slice_from_bytes(&bytes).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[1].account[..], bytes[96..128]);
        assert_eq!(entries[1].x[..], bytes[128..160]);
        assert_eq!(entries[1].y[..], bytes[160..192]);

        assert!(NodeEntry::slice_from_bytes(&bytes[..95]).is_none());
        assert_eq!(NodeEntry::slice_from_bytes(&[]).unwrap().len(), 0);
    }

    fn live(account: u8) -> NodeEntry {
        NodeEntry {
            account: [account; 32],
            ..NodeEntry::default()
        }
    }

    /// A view over `nodes` and `providers`, each segment's count its table's length.
    fn view<'a>(nodes: &'a [NodeEntry], providers: &'a [NodeEntry]) -> RegistryView<'a> {
        RegistryView {
            version: 0,
            node_count: nodes.len() as u16,
            provider_count: providers.len() as u16,
            redundancy_buffer: 0,
            nodes,
            providers,
        }
    }

    #[test]
    fn signer_is_bounded_by_node_count_and_table() {
        let nodes = [live(1), live(2), live(3), live(4)];
        let view = RegistryView {
            node_count: 3,
            ..view(&nodes, &[])
        };
        assert!(view.signer(2).is_ok());
        assert_eq!(view.signer(3), Err(AttestationError::InvalidSignersBitmap));

        let short = RegistryView {
            node_count: 8,
            ..view
        };
        assert_eq!(short.signer(4), Err(AttestationError::InvalidSignersBitmap));
    }

    #[test]
    fn a_hole_is_not_a_signer_and_keeps_the_other_slots_in_place() {
        let nodes = [live(1), NodeEntry::default(), live(3), live(4)];
        let view = view(&nodes, &[]);
        assert_eq!(view.signer(0).unwrap().account, [1; 32]);
        assert_eq!(view.signer(1), Err(AttestationError::InvalidSignersBitmap));
        assert_eq!(view.signer(2).unwrap().account, [3; 32]);
        assert_eq!(view.signer(3).unwrap().account, [4; 32]);

        assert_eq!(view.live_count(), 3);
        assert_eq!(view.live_slots().as_slice(), &[0, 2, 3]);
        assert_eq!(view.live_slots().slot(1), Some(2));
        assert_eq!(view.live_slots().slot(3), None);
    }

    /// The provider table with one live record per listed slot and holes elsewhere: slot `p` at
    /// index `p`, so slot 0 (reserved) is a hole.
    fn providers(slots: &[usize]) -> Vec<NodeEntry> {
        let mut table = Vec::new();
        for slot in slots {
            if table.len() <= *slot {
                table.resize(slot + 1, NodeEntry::default());
            }
            table[*slot] = live(200 + *slot as u8);
        }
        table
    }

    #[test]
    fn provider_bits_map_into_the_provider_table_with_no_node_padding() {
        let nodes = [live(1), NodeEntry::default(), live(3)];
        let providers = providers(&[1, 2]);
        let view = view(&nodes, &providers);
        // Three node slots and three provider slots (0 reserved): six records, not 67.
        assert_eq!((view.node_count, view.provider_count), (3, 3));
        assert_eq!(view.live_count(), 2);
        assert_eq!(view.live_slots().as_slice(), &[0, 2]);
        assert_eq!(
            view.signer(PROVIDER_BIT_BASE + 1).unwrap().account,
            [201; 32]
        );
        assert_eq!(
            view.signer(PROVIDER_BIT_BASE + 2).unwrap().account,
            [202; 32]
        );
        // A node bit past the node segment does not reach into the provider table.
        for bit in [3, 4, NODE_SLOTS - 1] {
            assert_eq!(
                view.signer(bit),
                Err(AttestationError::InvalidSignersBitmap)
            );
        }
    }

    #[test]
    fn a_hole_is_refused_in_the_provider_segment_too() {
        let nodes = [live(1)];
        let providers = providers(&[2]);
        let view = view(&nodes, &providers);
        // Slot 0 (reserved) and slot 1 are holes inside the table, slot 3 is past its end.
        for bit in [
            PROVIDER_BIT_BASE,
            PROVIDER_BIT_BASE + 1,
            PROVIDER_BIT_BASE + 3,
            255,
        ] {
            assert_eq!(
                view.signer(bit),
                Err(AttestationError::InvalidSignersBitmap)
            );
        }
        assert_eq!(
            view.signer(PROVIDER_BIT_BASE + 2).unwrap().account,
            [202; 32]
        );
        // The provider count bounds the table like the node count does.
        let short = RegistryView {
            provider_count: 2,
            ..view
        };
        assert_eq!(
            short.signer(PROVIDER_BIT_BASE + 2),
            Err(AttestationError::InvalidSignersBitmap)
        );
        // A node hole is refused as before.
        assert_eq!(view.signer(5), Err(AttestationError::InvalidSignersBitmap));
    }

    #[test]
    fn without_a_member_table_node_slots_stop_at_the_provider_segment() {
        let view = RegistryView {
            node_count: 100,
            ..view(&[], &[])
        };
        assert_eq!(view.live_count(), NODE_SLOTS as u32);
        assert_eq!(view.live_slots().slot(NODE_SLOTS - 1), Some(NODE_SLOTS - 1));
        assert_eq!(view.live_slots().slot(NODE_SLOTS), None);
    }

    #[test]
    fn without_a_member_table_every_slot_is_live() {
        let view = RegistryView {
            node_count: 5,
            ..view(&[], &[])
        };
        assert_eq!(view.live_slots().as_slice(), &[0, 1, 2, 3, 4]);
    }
}
