//! Error type for attestation verification.
//!
//! These are pure verification errors, mapped by downstream programs at the call boundary.
//! Account-borrow/deserialization errors are produced and handled by the caller (which owns the
//! framework-specific account I/O) and never cross the crate boundary.
//!
//! Enable the `thiserror` feature for [`std::error::Error`] and [`std::fmt::Display`] when using
//! this crate in off-chain tooling.

#[cfg_attr(feature = "thiserror", derive(thiserror::Error))]
#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub enum AttestationError {
    /// Aggregate Schnorr signature failed verification (recovered address mismatch,
    /// invalid coalition key, or invalid scalar `s`).
    #[cfg_attr(
        feature = "thiserror",
        error("aggregate Schnorr signature verification failed")
    )]
    InvalidAggregateSignature,
    /// A signature component was malformed (e.g. non-canonical scalar during the
    /// Schnorr→ECDSA conversion).
    #[cfg_attr(
        feature = "thiserror",
        error("malformed signature component (e.g. non-canonical Schnorr scalar)")
    )]
    InvalidSignature,
    /// `popcount(signers_bitmap) < signatures_required`.
    #[cfg_attr(
        feature = "thiserror",
        error("insufficient signers: popcount(signers_bitmap) < signatures_required")
    )]
    InsufficientSigners,
    /// `signers_bitmap` is not a subset of the deterministically derived selection bitmap.
    #[cfg_attr(
        feature = "thiserror",
        error("signers_bitmap is not a subset of the derived selection bitmap")
    )]
    SignersNotSubsetOfSelection,
    /// `signers_bitmap` has bits set outside `[0, node_count)`, or is otherwise invalid.
    #[cfg_attr(
        feature = "thiserror",
        error("invalid signers_bitmap (bits outside [0, node_count) or malformed)")
    )]
    InvalidSignersBitmap,
    /// Selection-group bitmap derivation failed (bad node count / group size, or the
    /// bounded sampling loop did not converge).
    #[cfg_attr(
        feature = "thiserror",
        error("selection-group bitmap derivation failed")
    )]
    GroupBitmapDerivationFailed,
    /// `ordered_signers.len()` does not equal `popcount(signers_bitmap)`.
    #[cfg_attr(
        feature = "thiserror",
        error("ordered_signers.len() does not match popcount(signers_bitmap)")
    )]
    SignerCountMismatch,
    /// The attestation's registry version does not match the provided snapshot.
    #[cfg_attr(feature = "thiserror", error("invalid registry version"))]
    InvalidRegistryVersion,
    /// A signer account is missing, extra, or does not match the registry slot.
    #[cfg_attr(
        feature = "thiserror",
        error("signer account missing, extra, or does not match the registry slot")
    )]
    MissingSignerAccount,
    /// A `Node` account does not match its expected bitmap index.
    #[cfg_attr(
        feature = "thiserror",
        error("node account index does not match bitmap")
    )]
    InvalidNodeIndex,
}

#[cfg(all(test, feature = "thiserror"))]
mod tests {
    use super::*;
    use std::error::Error;

    #[test]
    fn implements_error_and_display() {
        let err = AttestationError::InsufficientSigners;
        assert!(err.source().is_none());
        assert!(err.to_string().contains("insufficient signers"));
    }
}
