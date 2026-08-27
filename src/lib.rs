//! Molpha attestation aggregate-Schnorr verification.
#![cfg_attr(docsrs, feature(doc_cfg))]
//!
//! Framework-agnostic: the caller owns registry account types and passes plain data.
//! Verify via [`verify_attestation`] (resolved pubkeys) or [`verify_attestation_resolved`]
//! ([`RegistryView`] + [`NodeEntry`]s). [`resolve_registry_signers`] binds each set bit of the
//! signers bitmap to `nodes[bit]`.
//!
//! With the `solana` feature, [`solana`] accepts `&AccountInfo` and performs owner /
//! discriminator / length checks before verifying.
//!
//! # Usage
//! ```ignore
//! use molpha_verifier::{verify_attestation, Attestation};
//!
//! // `ordered_signers`: (x, y) pubkeys in ascending signers_bitmap bit order.
//! verify_attestation(&attestation, node_count, redundancy_buffer, &ordered_signers)?;
//! ```

#[doc(hidden)]
#[cfg(any(test, feature = "fixtures"))]
#[path = "../tests/fixtures/mod.rs"]
pub mod fixtures;

pub mod bitmap;
pub mod coalition;
pub mod error;
pub mod message;
pub mod onchain;
pub mod payload;
pub mod pop;
pub mod scalar;
pub mod selection;
#[cfg(feature = "solana")]
#[cfg_attr(docsrs, doc(cfg(feature = "solana")))]
pub mod solana;
pub mod state;
pub mod verify;

pub use error::AttestationError;
pub use onchain::*;
pub use payload::Attestation;
pub use payload::AttestationPayload;
pub use payload::SchnorrSignature;
pub use pop::{validate_key_and_verify_pop, NodePopError, NODE_POP_PREFIX};
pub use state::*;

pub use verify::{
    reconstruct_coalition_key, verify_aggregate_over_hash, verify_attestation, SignerXy,
};

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
