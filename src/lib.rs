//! Molpha attestation aggregate-Schnorr verification.
#![cfg_attr(docsrs, feature(doc_cfg))]
//!
//! Framework-agnostic: the caller owns registry account types and passes plain data.
//! Verify via [`verify()`] with a [`RegistryView`] of the registry snapshot the attestation
//! names. Each member of the snapshot ([`NodeEntry`]) carries the member's account address and
//! secp256k1 key, and each set bit of the signers bitmap binds to `registry.nodes[bit]`, so
//! signers are resolved from the snapshot itself.
//!
//! The 256 bits split in two: bits `[0, 64)` are operator nodes; bits `[64, 256)` are provider
//! signers, whose keys join the aggregate. Every set bit counts toward `signatures_required`, but
//! at most one provider bit may be set, so a provider round is `signatures_required - 1` nodes
//! plus the provider. [`verify_provenance()`] additionally requires a named provider.
//!
//! With the `solana` feature, [`solana`] accepts `&AccountInfo` and performs owner /
//! discriminator / shape checks before verifying.
//! With the `anchor` feature, attestation types implement Anchor serialization and account
//! adapter errors convert directly into `anchor_lang::error::Error`.
//!
//! # Usage
//! ```ignore
//! use molpha_verifier::{verify, Attestation};
//!
//! // `registry.nodes`: the snapshot's member table; `coalition_key` is optional.
//! verify(&attestation, &registry, Some(&coalition_key))?;
//! ```

#[doc(hidden)]
#[cfg(any(test, feature = "fixtures"))]
#[allow(dead_code)]
pub mod fixtures {
    // Keep this module inline so Anchor's IDL source parser does not try to resolve the
    // test-only fixture as a conventional `src/fixtures.rs` module.
    include!("../tests/fixtures/mod.rs");
}

pub mod bitmap;
pub mod coalition;
pub mod error;
pub mod message;
pub mod onchain;
pub mod partial;
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
pub use partial::{verify_partial_signature_equation, NonceEquationError};
pub use payload::Attestation;
pub use payload::AttestationPayload;
pub use payload::SchnorrSignature;
pub use pop::{
    key_rotation_digest, validate_key_and_verify_pop, validate_provider_key_and_verify_pop,
    verify_key_rotation, KeyRotationError, KeyRotationProof, NodePopError,
    NODE_KEY_ROTATION_PREFIX, NODE_POP_PREFIX, PROVIDER_POP_PREFIX,
};
pub use state::*;

pub use verify::{
    coalition_key, reconstruct_coalition_key, verify, verify_aggregate_over_hash,
    verify_aggregate_over_hash_with_coalition_key, verify_provenance,
};

pub use bitmap::{derive_group_bitmap, effective_selection_size, for_each_set_bit, Bitmap};
pub use coalition::{CoalitionAccumulator, CoalitionKey};
pub use message::{compute_message_hash, MESSAGE_PREFIX};
pub use scalar::{
    eth_address_from_uncompressed_pubkey, evm_schnorr_ecdsa_inputs,
    secp256k1_scalar_is_valid_nonzero,
};
pub use selection::{
    attestation_selection, check_quorum, derive_selection_bitmap, node_quorum, verify_selection,
    SELECTION_SEED_PREFIX, SELECTION_WINDOW_MS,
};
