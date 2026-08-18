//! Molpha attestation aggregate-Schnorr verification.
//!
//! A framework-agnostic library (no Anchor / Pinocchio dependency): the downstream program owns the
//! registry account types and reads them, then passes plain data in. Verify a Molpha
//! [`Attestation`] either from already-resolved signer pubkeys ([`verify_attestation`]) or from
//! parsed registry entries plus a [`RegistryView`] ([`verify_attestation_resolved`]).
//!
//! # Usage
//! ```ignore
//! use molpha_verifier::{verify_attestation, Attestation};
//!
//! // `ordered_signers` are the signing nodes' (x, y) pubkeys in ascending signers_bitmap bit order.
//! verify_attestation(&attestation, node_count, redundancy_buffer, &ordered_signers)?;
//! ```

pub mod bitmap;
pub mod coalition;
pub mod error;
pub mod message;
pub mod onchain;
pub mod payload;
pub mod scalar;
pub mod selection;
pub mod state;
pub mod verify;

pub use error::AttestationError;
pub use onchain::*;
pub use payload::Attestation;
pub use payload::AttestationPayload;
pub use payload::SchnorrSignature;
pub use state::*;

// High-level verification API.
pub use verify::{
    reconstruct_coalition_key, reconstruct_coalition_key_compressed, verify_aggregate_over_hash,
    verify_attestation, verify_attestation_compressed, SignerXy,
};

// Primitives commonly composed by on-chain callers.
pub use bitmap::{
    bitmap_is_subset_u256, bitmap_load, derive_group_bitmap, effective_selection_size,
    for_each_set_bit_u256,
};
pub use coalition::CoalitionAccumulator;
pub use message::{compute_message_hash, MESSAGE_PREFIX};
pub use scalar::{
    eth_address_from_uncompressed_pubkey, evm_schnorr_ecdsa_inputs,
    secp256k1_scalar_is_valid_nonzero,
};
pub use selection::{derive_selection_bitmap, SELECTION_SEED_PREFIX};
