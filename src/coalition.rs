//! Incremental coalition-key accumulation (`Σ signer pubkeys`) over secp256k1.

use libsecp256k1::util::{TAG_PUBKEY_EVEN, TAG_PUBKEY_ODD};
use libsecp256k1::{
    curve::{Affine, Field, Jacobian},
    PublicKey, PublicKeyFormat,
};

use crate::error::AttestationError;

/// Affine coalition key `Σ X_i = (x, y)`, big-endian: an untrusted verification input.
///
/// Supplying it lets the verifier check its Jacobian sum against the key instead of normalizing
/// the sum with a field inversion (see [`CoalitionAccumulator::compressed_pubkey_with_key`]).
/// It is a property of the point, not of the verifier's arithmetic: any secp256k1 library
/// computes it as the plain sum of the signers' public keys, in any order.
///
/// Not part of the signed message or the cross-VM [`crate::Attestation`]; carry it next to the
/// attestation, e.g. in Solana instruction data.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(
    all(feature = "borsh", not(feature = "anchor")),
    derive(borsh::BorshSerialize, borsh::BorshDeserialize)
)]
#[cfg_attr(
    feature = "anchor",
    derive(anchor_lang::AnchorSerialize, anchor_lang::AnchorDeserialize)
)]
pub struct CoalitionKey {
    pub x: [u8; 32],
    pub y: [u8; 32],
}

/// Load a curve point from registry-stored `(x, y)` without an on-curve re-check.
///
/// Coordinates are validated at registration; the hot path only needs field parsing.
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

/// Incremental coalition accumulator without `PublicKey::combine` / `Vec`.
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
            // Variable-time add: all inputs are public on-chain data.
            self.jacobian = self.jacobian.add_ge_var(&ge, None);
        }
        Ok(())
    }

    /// Compressed coalition key, normalizing the Jacobian sum with a field inversion.
    ///
    /// Reference path. On-chain callers should prefer [`Self::compressed_pubkey_with_key`], which
    /// replaces the inversion with a check of a supplied [`CoalitionKey`].
    #[inline(always)]
    pub fn compressed_pubkey(&self) -> Result<[u8; 33], AttestationError> {
        let jacobian = self.finished_sum()?;
        Ok(compress_affine(Affine::from_gej(jacobian)))
    }

    /// Compressed coalition key, checking a caller-supplied affine key projectively.
    ///
    /// `key` is untrusted (e.g. instruction data). It is accepted only when both coordinates
    /// parse to canonical field elements (`< p`) and `X ≡ x·Z²`, `Y ≡ y·Z³ (mod p)` against this
    /// accumulator's Jacobian sum `(X, Y, Z)`. The sum is not infinity, so `Z ≠ 0` and those
    /// equations pin `(x, y)` to its affine form whatever formulas or signer order produced the
    /// representative. A wrong key fails with [`AttestationError::InvalidCoalitionKey`]; it
    /// cannot select another key.
    #[inline(always)]
    pub fn compressed_pubkey_with_key(
        &self,
        key: &CoalitionKey,
    ) -> Result<[u8; 33], AttestationError> {
        let jacobian = self.finished_sum()?;
        let mut x = Field::default();
        let mut y = Field::default();
        if !x.set_b32(&key.x) || !y.set_b32(&key.y) {
            return Err(AttestationError::InvalidCoalitionKey);
        }
        let z2 = jacobian.z.sqr();
        let z3 = z2 * jacobian.z;
        if !(x * z2).eq_var(&jacobian.x) || !(y * z3).eq_var(&jacobian.y) {
            return Err(AttestationError::InvalidCoalitionKey);
        }
        let mut elem = Affine::default();
        elem.set_xy(&x, &y);
        Ok(compress_affine(elem))
    }

    /// Off-chain helper: the affine [`CoalitionKey`] of the accumulated sum (one field inversion).
    pub fn coalition_key(&self) -> Result<CoalitionKey, AttestationError> {
        let mut elem = Affine::from_gej(self.finished_sum()?);
        elem.x.normalize();
        elem.y.normalize();
        let mut key = CoalitionKey {
            x: [0u8; 32],
            y: [0u8; 32],
        };
        elem.x.fill_b32(&mut key.x);
        elem.y.fill_b32(&mut key.y);
        Ok(key)
    }

    /// The Jacobian sum, rejecting an empty set and the point at infinity.
    ///
    /// `libsecp256k1` flags infinity separately from `Z`, so this check must stay explicit even
    /// on the keyed path.
    #[inline(always)]
    fn finished_sum(&self) -> Result<&Jacobian, AttestationError> {
        if !self.has_point || self.jacobian.is_infinity() {
            return Err(AttestationError::InvalidAggregateSignature);
        }
        Ok(&self.jacobian)
    }
}

#[inline(always)]
fn compress_affine(mut elem: Affine) -> [u8; 33] {
    elem.x.normalize_var();
    elem.y.normalize_var();
    let mut out = [0u8; 33];
    elem.x
        .fill_b32((&mut out[1..33]).try_into().expect("32-byte slice"));
    out[0] = if elem.y.is_odd() {
        TAG_PUBKEY_ODD
    } else {
        TAG_PUBKEY_EVEN
    };
    out
}

/// Build a `PublicKey` from stored affine coordinates (on-curve check, no decompress).
///
/// `uncompressed_scratch` is reused across the signer loop (`0x04 || x || y`).
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
        let key = CoalitionKey {
            x: [1u8; 32],
            y: [1u8; 32],
        };
        assert_eq!(
            CoalitionAccumulator::default().compressed_pubkey_with_key(&key),
            Err(AttestationError::InvalidAggregateSignature)
        );
    }

    fn accumulate(keys: &[PublicKey]) -> CoalitionAccumulator {
        let mut acc = CoalitionAccumulator::default();
        for pk in keys {
            let (x, y) = xy_of(pk);
            acc.add_stored_xy(&x, &y).expect("accumulate");
        }
        acc
    }

    fn add_be(a: &[u8; 32], b: &[u8; 32]) -> Option<[u8; 32]> {
        let mut out = [0u8; 32];
        let mut carry = 0u16;
        for i in (0..32).rev() {
            let sum = a[i] as u16 + b[i] as u16 + carry;
            out[i] = sum as u8;
            carry = sum >> 8;
        }
        (carry == 0).then_some(out)
    }

    #[test]
    fn coalition_key_is_the_combined_point() {
        let keys = [fixture_key(0), fixture_key(1), fixture_key(2)];
        let combined = PublicKey::combine(&keys).expect("combine");
        let (x, y) = xy_of(&combined);
        assert_eq!(
            accumulate(&keys).coalition_key().expect("key"),
            CoalitionKey { x, y }
        );
    }

    #[test]
    fn keyed_path_matches_inversion_path_in_any_order() {
        let keys = [fixture_key(0), fixture_key(1), fixture_key(2)];
        let acc = accumulate(&keys);
        let key = acc.coalition_key().expect("key");
        let expected = acc.compressed_pubkey().expect("compressed");
        assert_eq!(acc.compressed_pubkey_with_key(&key), Ok(expected));

        // Same point, different Jacobian representative: the key does not depend on it.
        let reversed = accumulate(&[keys[2], keys[1], keys[0]]);
        assert_eq!(reversed.compressed_pubkey_with_key(&key), Ok(expected));

        // A single signer's own key is its coalition key (`Z = 1`).
        let (x, y) = xy_of(&keys[1]);
        assert_eq!(
            accumulate(&keys[1..2]).compressed_pubkey_with_key(&CoalitionKey { x, y }),
            Ok(keys[1].serialize_compressed())
        );
    }

    #[test]
    fn keyed_path_rejects_wrong_keys() {
        let keys = [fixture_key(0), fixture_key(1), fixture_key(2)];
        let acc = accumulate(&keys);
        let key = acc.coalition_key().expect("key");
        let (other_x, other_y) = xy_of(&keys[0]);

        let mut flipped_x = key;
        flipped_x.x[31] ^= 0x01;
        let mut flipped_y = key;
        flipped_y.y[31] ^= 0x01;
        let mut bad = vec![
            flipped_x,
            flipped_y,
            // Same x, other parity: the Y equation must reject it.
            CoalitionKey {
                x: key.x,
                y: negate_y(&key.y),
            },
            CoalitionKey {
                x: other_x,
                y: other_y,
            },
            CoalitionKey {
                x: [0u8; 32],
                y: [0u8; 32],
            },
            CoalitionKey {
                x: key.x,
                y: FIELD_PRIME,
            },
            CoalitionKey {
                x: FIELD_PRIME,
                y: key.y,
            },
            CoalitionKey {
                x: [0xff; 32],
                y: key.y,
            },
        ];
        // Non-canonical encodings of the right residues must be refused, not reduced.
        if let Some(x) = add_be(&key.x, &FIELD_PRIME) {
            bad.push(CoalitionKey { x, y: key.y });
        }
        if let Some(y) = add_be(&key.y, &FIELD_PRIME) {
            bad.push(CoalitionKey { x: key.x, y });
        }

        for wrong in bad {
            assert_eq!(
                acc.compressed_pubkey_with_key(&wrong),
                Err(AttestationError::InvalidCoalitionKey),
                "key {wrong:02x?} must be rejected"
            );
        }
    }
}
