//! Framework-agnostic registry snapshot view.
//!
//! Canonical account types live in the downstream program. Callers pass a [`RegistryView`] whose
//! `nodes` carry each member's account address and secp256k1 key, so signers are resolved from
//! the snapshot itself.

use crate::error::AttestationError;

/// Maximum registry membership (signer bitmaps are 256-bit).
pub const MAX_REGISTRY_NODES: usize = 256;

/// Secp256k1 affine coordinates `(x, y)`, big-endian.
pub type SignerXy = ([u8; 32], [u8; 32]);

/// Immutable, version-addressed registry snapshot.
///
/// A member keeps its slot (its signer bit) for as long as it is in the snapshot: removing a
/// node leaves a vacant slot instead of moving the last member into it. `node_count` is therefore
/// the number of slots, **holes included**, and the count of live members is
/// [`RegistryView::live_count`]. A hole is an all-zero [`NodeEntry`]; trailing holes are never
/// stored, so the last slot is always live.
///
/// `nodes` is borrowed so on-chain callers can view the account's member table without copying
/// (see [`NodeEntry::slice_from_bytes`]). Selection-only callers may pass `&[]`, which reads as a
/// registry without holes; verification then fails with
/// [`AttestationError::InvalidSignersBitmap`].
#[derive(Clone, Copy, Debug)]
pub struct RegistryView<'a> {
    pub version: u32,
    /// Slots in the member table, holes included.
    pub node_count: u16,
    pub redundancy_buffer: u8,
    /// Ordered slots; only `nodes[..node_count]` is populated.
    pub nodes: &'a [NodeEntry],
}

impl RegistryView<'_> {
    /// The member bound to signer bit `bit`.
    ///
    /// Errors unless `bit < node_count`, the member table covers it and the slot is live.
    #[inline(always)]
    pub fn signer(&self, bit: usize) -> Result<&NodeEntry, AttestationError> {
        if bit >= usize::from(self.node_count) {
            return Err(AttestationError::InvalidSignersBitmap);
        }
        match self.nodes.get(bit) {
            Some(node) if !node.is_vacant() => Ok(node),
            _ => Err(AttestationError::InvalidSignersBitmap),
        }
    }

    /// The live slots in ascending order.
    ///
    /// Without a member table (`nodes` shorter than `node_count`, for example the empty slice of
    /// a selection-only caller) every slot is taken to be live.
    pub fn live_slots(&self) -> LiveSlots {
        let slots = usize::from(self.node_count).min(MAX_REGISTRY_NODES);
        let mut out = LiveSlots {
            slots: [0; MAX_REGISTRY_NODES],
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

    /// Number of live members (`node_count` minus the holes).
    pub fn live_count(&self) -> u32 {
        self.live_slots().len() as u32
    }
}

/// The live slots of a snapshot in ascending order, as returned by [`RegistryView::live_slots`].
#[derive(Clone, Copy, Debug)]
pub struct LiveSlots {
    slots: [u16; MAX_REGISTRY_NODES],
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

    #[test]
    fn signer_is_bounded_by_node_count_and_table() {
        let nodes = [live(1), live(2), live(3), live(4)];
        let view = RegistryView {
            version: 0,
            node_count: 3,
            redundancy_buffer: 0,
            nodes: &nodes,
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
        let view = RegistryView {
            version: 0,
            node_count: 4,
            redundancy_buffer: 0,
            nodes: &nodes,
        };
        assert_eq!(view.signer(0).unwrap().account, [1; 32]);
        assert_eq!(view.signer(1), Err(AttestationError::InvalidSignersBitmap));
        assert_eq!(view.signer(2).unwrap().account, [3; 32]);
        assert_eq!(view.signer(3).unwrap().account, [4; 32]);

        assert_eq!(view.live_count(), 3);
        assert_eq!(view.live_slots().as_slice(), &[0, 2, 3]);
        assert_eq!(view.live_slots().slot(1), Some(2));
        assert_eq!(view.live_slots().slot(3), None);
    }

    #[test]
    fn without_a_member_table_every_slot_is_live() {
        let view = RegistryView {
            version: 0,
            node_count: 5,
            redundancy_buffer: 0,
            nodes: &[],
        };
        assert_eq!(view.live_slots().as_slice(), &[0, 1, 2, 3, 4]);
    }
}
