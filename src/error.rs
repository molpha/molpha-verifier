//! Attestation verification errors.
//!
//! Pure verification failures; account I/O errors stay with the caller. Enable `thiserror` for
//! [`std::error::Error`] / [`std::fmt::Display`] in off-chain tooling.

#[cfg_attr(feature = "thiserror", derive(thiserror::Error))]
#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub enum AttestationError {
    /// Aggregate Schnorr verification failed (address mismatch, bad coalition key, or invalid `s`).
    #[cfg_attr(
        feature = "thiserror",
        error("aggregate Schnorr signature verification failed")
    )]
    InvalidAggregateSignature,
    /// Malformed signature component (e.g. non-canonical Schnorr→ECDSA scalar).
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
    /// `signers_bitmap` is not a subset of the derived selection bitmap.
    #[cfg_attr(
        feature = "thiserror",
        error("signers_bitmap is not a subset of the derived selection bitmap")
    )]
    SignersNotSubsetOfSelection,
    /// Bits set outside `[0, node_count)`, or otherwise invalid bitmap.
    #[cfg_attr(
        feature = "thiserror",
        error("invalid signers_bitmap (bits outside [0, node_count) or malformed)")
    )]
    InvalidSignersBitmap,
    /// Selection derivation failed (bad parameters or sampling did not converge).
    #[cfg_attr(
        feature = "thiserror",
        error("selection-group bitmap derivation failed")
    )]
    GroupBitmapDerivationFailed,
    /// `ordered_signers.len()` ≠ `popcount(signers_bitmap)`.
    #[cfg_attr(
        feature = "thiserror",
        error("ordered_signers.len() does not match popcount(signers_bitmap)")
    )]
    SignerCountMismatch,
    /// Attestation registry version does not match the snapshot.
    #[cfg_attr(feature = "thiserror", error("invalid registry version"))]
    InvalidRegistryVersion,
    /// Signer account missing, extra, or does not match the registry slot.
    #[cfg_attr(
        feature = "thiserror",
        error("signer account missing, extra, or does not match the registry slot")
    )]
    MissingSignerAccount,
    /// `Node` account index does not match the bitmap.
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
