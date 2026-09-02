//! Framework-agnostic inputs to signer resolution.
//!
//! Canonical account types live in the downstream program. Callers pass a [`RegistryView`] and
//! already-parsed [`NodeEntry`]s.

/// Maximum registry membership (signer bitmaps are 256-bit).
pub const MAX_REGISTRY_NODES: usize = 256;

/// Immutable, version-addressed registry snapshot.
///
/// `nodes` is borrowed so on-chain callers can pass `&registry.nodes` without copying.
#[derive(Clone, Copy, Debug)]
pub struct RegistryView<'a> {
    pub version: u32,
    pub node_count: u16,
    pub redundancy_buffer: u8,
    /// Ordered node account pubkeys; only `nodes[..node_count]` is populated.
    pub nodes: &'a [[u8; 32]],
}

/// One signer: account pubkey plus secp256k1 affine coordinates (big-endian).
///
/// `account` must equal `registry.nodes[bit]` for the corresponding set bit.
#[derive(Clone, Copy, Debug)]
pub struct NodeEntry {
    pub account: [u8; 32],
    pub x: [u8; 32],
    pub y: [u8; 32],
}
