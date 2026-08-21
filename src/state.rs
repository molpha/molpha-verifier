//! Plain, framework-agnostic inputs to signer resolution.
//!
//! The canonical Molpha registry **account** types (`Registry`, `RegistryState`, `Node`) live in the
//! downstream program — they are framework-specific (Anchor `#[account]`, Pinocchio, …). This crate
//! only needs the handful of plain fields the resolver reads, so callers pass a [`RegistryView`] and
//! a slice of already-parsed [`NodeEntry`]s.

/// Maximum registry membership. Signer bitmaps are fixed 256-bit values.
pub const MAX_REGISTRY_NODES: usize = 256;

/// Plain view of an immutable, version-addressed registry snapshot.
///
/// The caller builds this from its own registry account (whatever framework it uses). `nodes` is a
/// borrowed slice so on-chain callers can pass `&registry.nodes` without copying the 8 KB array.
#[derive(Clone, Copy, Debug)]
pub struct RegistryView<'a> {
    pub version: u32,
    pub node_count: u16,
    pub redundancy_buffer: u8,
    /// Ordered node account pubkeys; only `nodes[..node_count]` is populated.
    pub nodes: &'a [[u8; 32]],
}

/// A single signer's account pubkey plus secp256k1 coordinates, already owner-checked and parsed
/// by the caller.
///
/// `account` must equal `registry.nodes[bit]` for the corresponding set bit. `x` / `y` are the
/// node's secp256k1 public-key affine coordinates (big-endian), as stored in the program's `Node`
/// account.
#[derive(Clone, Copy, Debug)]
pub struct NodeEntry {
    pub account: [u8; 32],
    pub x: [u8; 32],
    pub y: [u8; 32],
}
