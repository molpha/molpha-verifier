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
/// `nodes` is borrowed so on-chain callers can view the account's member table without copying
/// (see [`NodeEntry::slice_from_bytes`]). Selection-only callers may pass `&[]`; verification
/// then fails with [`AttestationError::InvalidSignersBitmap`].
#[derive(Clone, Copy, Debug)]
pub struct RegistryView<'a> {
    pub version: u32,
    pub node_count: u16,
    pub redundancy_buffer: u8,
    /// Ordered members; only `nodes[..node_count]` is populated.
    pub nodes: &'a [NodeEntry],
}

impl RegistryView<'_> {
    /// The member bound to signer bit `bit`.
    ///
    /// Errors unless `bit < node_count` and the member table covers it.
    #[inline(always)]
    pub fn signer(&self, bit: usize) -> Result<&NodeEntry, AttestationError> {
        if bit >= usize::from(self.node_count) {
            return Err(AttestationError::InvalidSignersBitmap);
        }
        self.nodes
            .get(bit)
            .ok_or(AttestationError::InvalidSignersBitmap)
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

    #[test]
    fn signer_is_bounded_by_node_count_and_table() {
        let nodes = [NodeEntry::default(); 4];
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
}
