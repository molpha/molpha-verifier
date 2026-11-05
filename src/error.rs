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
    /// `popcount(signers_bitmap) < signatures_required`, or `signatures_required == 0`.
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
    /// Empty bitmap, more than one provider bit, bits set outside `[0, node_count)` or the
    /// registry's member table, or a set bit (node or provider) on a hole.
    #[cfg_attr(
        feature = "thiserror",
        error("invalid signers_bitmap (empty, more than one provider bit, or bits outside the registry)")
    )]
    InvalidSignersBitmap,
    /// Selection derivation failed (bad parameters or sampling did not converge).
    #[cfg_attr(
        feature = "thiserror",
        error("selection-group bitmap derivation failed")
    )]
    GroupBitmapDerivationFailed,
    /// Attestation registry version does not match the snapshot.
    #[cfg_attr(feature = "thiserror", error("invalid registry version"))]
    InvalidRegistryVersion,
    /// Node index outside the registry's populated members.
    #[cfg_attr(
        feature = "thiserror",
        error("node index is outside the registry's populated members")
    )]
    InvalidNodeIndex,
    /// Supplied coalition key is non-canonical or is not the affine sum of the signer keys.
    #[cfg_attr(
        feature = "thiserror",
        error("coalition key is not the sum of the signer keys")
    )]
    InvalidCoalitionKey,
    /// The registry version's grace window had ended by the round's timestamp: it was
    /// superseded, and no longer verifies new rounds.
    #[cfg_attr(
        feature = "thiserror",
        error("registry version was retired before the round's timestamp")
    )]
    RegistryRetired,
    /// The attestation verifies, but no set provider bit names the required provider.
    #[cfg_attr(
        feature = "thiserror",
        error("no set provider bit names the required provider")
    )]
    ProviderAbsent,
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
