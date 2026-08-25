//! Incremental coalition-key accumulation (`Σ signer pubkeys`) over secp256k1.
//!
//! Pure, anchor-free. Moved from the Molpha program's `utils/account_layout.rs`
//! (only the curve-math helpers; the anchor/PDA account readers stay in the program).
//! `error!()`/`require!()` are replaced with plain [`AttestationError`] returns.

use libsecp256k1::util::{TAG_PUBKEY_EVEN, TAG_PUBKEY_ODD};
use libsecp256k1::{
    curve::{Affine, Field, Jacobian},
    PublicKey, PublicKeyFormat,
};

use crate::error::AttestationError;

/// Load a curve point from registry-stored `(x, y)` without an on-curve re-check.
///
/// Coordinates are validated at registration; the data-update hot path only needs field parsing.
#[inline(always)]
pub fn affine_from_stored_secp_xy(x: &[u8; 32], y: &[u8; 32]) -> Result<Affine, AttestationError> {
    if *x == [0u8; 32] || *y == [0u8; 32] {
        return Err(AttestationError::InvalidAggregateSignature);
    }
    let mut fx = Field::default();
    let mut fy = Field::default();
    if !fx.set_b32(x) || !fy.set_b32(y) {
        return Err(AttestationError::InvalidAggregateSignature);
    }
    let mut ge = Affine::default();
    ge.set_xy(&fx, &fy);
    Ok(ge)
}

/// Incremental coalition accumulator (`Σ signer pubkeys`) without `PublicKey::combine` / `Vec`.
#[derive(Default)]
pub struct CoalitionAccumulator {
    jacobian: Jacobian,
    has_point: bool,
}

impl CoalitionAccumulator {
    #[inline(always)]
    pub fn add_stored_xy(&mut self, x: &[u8; 32], y: &[u8; 32]) -> Result<(), AttestationError> {
        let ge = affine_from_stored_secp_xy(x, y)?;
        if !self.has_point {
            self.jacobian = Jacobian::from_ge(&ge);
            self.has_point = true;
        } else {
            // `add_ge_var` over `add_ge`: one fewer field multiplication and none of the
            // constant-time `cmov` scaffolding. Every input here — registry pubkeys and a public
            // signers bitmap — is public data already on chain, so there is no secret for the
            // variable-time branches to leak.
            self.jacobian = self.jacobian.add_ge_var(&ge, None);
        }
        Ok(())
    }

    #[inline(always)]
    pub fn compressed_pubkey(&self) -> Result<[u8; 33], AttestationError> {
        if !self.has_point {
            return Err(AttestationError::InvalidAggregateSignature);
        }
        if self.jacobian.is_infinity() {
            return Err(AttestationError::InvalidAggregateSignature);
        }
        let mut elem = Affine::from_gej(&self.jacobian);
        elem.x.normalize_var();
        elem.y.normalize_var();
        let mut out = [0u8; 33];
        let mut x_be = [0u8; 32];
        elem.x.fill_b32(&mut x_be);
        out[1..33].copy_from_slice(&x_be);
        out[0] = if elem.y.is_odd() {
            TAG_PUBKEY_ODD
        } else {
            TAG_PUBKEY_EVEN
        };
        Ok(out)
    }
}

/// Build a `libsecp256k1::PublicKey` from stored affine coordinates (on-curve check, no decompress).
///
/// `uncompressed_scratch` is reused across the signer loop (65-byte `0x04 || x || y`).
#[inline(always)]
pub fn public_key_from_affine_xy(
    uncompressed_scratch: &mut [u8; 65],
    x: &[u8; 32],
    y: &[u8; 32],
) -> Result<PublicKey, AttestationError> {
    if *x == [0u8; 32] || *y == [0u8; 32] {
        return Err(AttestationError::InvalidAggregateSignature);
    }
    uncompressed_scratch[0] = 0x04;
    uncompressed_scratch[1..33].copy_from_slice(x);
    uncompressed_scratch[33..65].copy_from_slice(y);
    PublicKey::parse_slice(uncompressed_scratch.as_ref(), Some(PublicKeyFormat::Full))
        .map_err(|_| AttestationError::InvalidAggregateSignature)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn coalition_accumulator_matches_public_key_combine() {
        let fixture_compressed: [[u8; 33]; 3] = [
            [
                0x03, 0xc0, 0x95, 0x27, 0xe9, 0x78, 0xf6, 0xea, 0x69, 0xf0, 0xc6, 0xb7, 0xac, 0x0f,
                0xb6, 0x3a, 0xd0, 0x81, 0xa8, 0xa2, 0x91, 0x15, 0x1c, 0x5a, 0x0b, 0x11, 0x5c, 0xce,
                0x43, 0x57, 0x51, 0xbe, 0x7d,
            ],
            [
                0x02, 0x64, 0xa7, 0x27, 0x04, 0xf3, 0x9f, 0x8d, 0xd1, 0x7f, 0x20, 0xd7, 0x1c, 0x5b,
                0x21, 0xf3, 0x7b, 0x58, 0x52, 0x65, 0x6b, 0xc0, 0x55, 0x54, 0x42, 0xbf, 0x72, 0x72,
                0x22, 0xf2, 0x9d, 0x7e, 0x58,
            ],
            [
                0x02, 0x75, 0xae, 0x1e, 0x3d, 0xac, 0x00, 0xeb, 0x7d, 0xf0, 0x2e, 0x9f, 0xe8, 0xd9,
                0x70, 0x9c, 0x8a, 0x2c, 0x09, 0xa1, 0x1e, 0xd4, 0xf7, 0xd9, 0xaa, 0x46, 0xa7, 0xde,
                0xa6, 0xcf, 0x37, 0x6d, 0x7f,
            ],
        ];
        let pks: Vec<PublicKey> = fixture_compressed
            .iter()
            .map(|c| {
                PublicKey::parse_slice(c, Some(PublicKeyFormat::Compressed))
                    .expect("fixture compressed key")
            })
            .collect();
        let combined = PublicKey::combine(&pks).expect("combine");
        let mut acc = CoalitionAccumulator::default();
        for pk in &pks {
            let full = pk.serialize();
            let x: [u8; 32] = full[1..33].try_into().unwrap();
            let y: [u8; 32] = full[33..65].try_into().unwrap();
            acc.add_stored_xy(&x, &y).expect("accumulate");
        }
        assert_eq!(
            acc.compressed_pubkey().expect("compressed"),
            combined.serialize_compressed()
        );
    }

    /// secp256k1 field prime `p`.
    const FIELD_PRIME: [u8; 32] = [
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF,
        0xFC, 0x2F,
    ];

    fn xy_of(pk: &PublicKey) -> ([u8; 32], [u8; 32]) {
        let full = pk.serialize();
        (
            full[1..33].try_into().unwrap(),
            full[33..65].try_into().unwrap(),
        )
    }

    /// `p - y`, big-endian — the y coordinate of `-P`.
    fn negate_y(y: &[u8; 32]) -> [u8; 32] {
        let mut out = [0u8; 32];
        let mut borrow = 0i16;
        for i in (0..32).rev() {
            let diff = FIELD_PRIME[i] as i16 - y[i] as i16 - borrow;
            if diff < 0 {
                out[i] = (diff + 256) as u8;
                borrow = 1;
            } else {
                out[i] = diff as u8;
                borrow = 0;
            }
        }
        out
    }

    fn fixture_key(index: usize) -> PublicKey {
        let compressed: [[u8; 33]; 3] = [
            [
                0x03, 0xc0, 0x95, 0x27, 0xe9, 0x78, 0xf6, 0xea, 0x69, 0xf0, 0xc6, 0xb7, 0xac, 0x0f,
                0xb6, 0x3a, 0xd0, 0x81, 0xa8, 0xa2, 0x91, 0x15, 0x1c, 0x5a, 0x0b, 0x11, 0x5c, 0xce,
                0x43, 0x57, 0x51, 0xbe, 0x7d,
            ],
            [
                0x02, 0x64, 0xa7, 0x27, 0x04, 0xf3, 0x9f, 0x8d, 0xd1, 0x7f, 0x20, 0xd7, 0x1c, 0x5b,
                0x21, 0xf3, 0x7b, 0x58, 0x52, 0x65, 0x6b, 0xc0, 0x55, 0x54, 0x42, 0xbf, 0x72, 0x72,
                0x22, 0xf2, 0x9d, 0x7e, 0x58,
            ],
            [
                0x02, 0x75, 0xae, 0x1e, 0x3d, 0xac, 0x00, 0xeb, 0x7d, 0xf0, 0x2e, 0x9f, 0xe8, 0xd9,
                0x70, 0x9c, 0x8a, 0x2c, 0x09, 0xa1, 0x1e, 0xd4, 0xf7, 0xd9, 0xaa, 0x46, 0xa7, 0xde,
                0xa6, 0xcf, 0x37, 0x6d, 0x7f,
            ],
        ];
        PublicKey::parse_slice(&compressed[index], Some(PublicKeyFormat::Compressed))
            .expect("fixture compressed key")
    }

    /// Two identical signers hit the point-doubling branch of the addition, not the generic one.
    #[test]
    fn coalition_accumulator_doubles_a_repeated_signer() {
        let pk = fixture_key(0);
        let (x, y) = xy_of(&pk);
        let combined = PublicKey::combine(&[pk, pk]).expect("combine duplicate");

        let mut acc = CoalitionAccumulator::default();
        acc.add_stored_xy(&x, &y).expect("first");
        acc.add_stored_xy(&x, &y).expect("second");
        assert_eq!(
            acc.compressed_pubkey().expect("compressed"),
            combined.serialize_compressed()
        );
    }

    /// A signer set summing to the point at infinity (`P + (-P)`) has no compressed encoding and
    /// must be rejected rather than silently normalized.
    #[test]
    fn coalition_accumulator_rejects_sum_at_infinity() {
        let pk = fixture_key(1);
        let (x, y) = xy_of(&pk);
        let neg_y = negate_y(&y);

        let mut acc = CoalitionAccumulator::default();
        acc.add_stored_xy(&x, &y).expect("P");
        acc.add_stored_xy(&x, &neg_y).expect("-P");
        assert_eq!(
            acc.compressed_pubkey(),
            Err(AttestationError::InvalidAggregateSignature)
        );
    }

    /// `P + (-P) + P == P` — the infinity intermediate must not poison later additions.
    #[test]
    fn coalition_accumulator_recovers_from_infinity_intermediate() {
        let pk = fixture_key(2);
        let (x, y) = xy_of(&pk);
        let neg_y = negate_y(&y);

        let mut acc = CoalitionAccumulator::default();
        acc.add_stored_xy(&x, &y).expect("P");
        acc.add_stored_xy(&x, &neg_y).expect("-P");
        acc.add_stored_xy(&x, &y).expect("P again");
        assert_eq!(
            acc.compressed_pubkey().expect("compressed"),
            pk.serialize_compressed()
        );
    }

    #[test]
    fn accumulator_is_empty_before_any_signer() {
        assert_eq!(
            CoalitionAccumulator::default().compressed_pubkey(),
            Err(AttestationError::InvalidAggregateSignature)
        );
    }
}
