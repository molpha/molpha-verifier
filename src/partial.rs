//! Partial-signature equation checks for nonce-slot reuse evidence.
//!
//! A FROST-style co-signer that emits two verifying partials against one committed nonce pair
//! leaks its share. The offence is defined at the equation level: two triples `(b, c, s)` that
//! each satisfy `s*G == R1 + b*R2 + c*X` against a single committed `(R1, R2)` prove two signing
//! evaluations over one nonce. This module only answers "does this triple satisfy the equation",
//! never "where did `b` and `c` come from" — the caller supplies the challenge scalars verbatim,
//! so no commitment list or signed message needs to reach the chain.
//!
//! Producing even one satisfying triple requires knowledge of `(r1, r2, x)`, so a filer cannot
//! fabricate a second triple from an observed one without solving a discrete log.

use libsecp256k1::curve::{Affine, Jacobian};
use solana_secp256k1_recover::secp256k1_recover;

use crate::{
    coalition::{affine_from_stored_secp_xy, public_key_from_affine_xy},
    scalar::{
        mul_mod, negate_mod_n, secp256k1_ecdsa_normalize_low_s, secp256k1_scalar_is_valid_nonzero,
    },
    SignerXy,
};

/// Malformed partial-signature evidence.
#[cfg_attr(feature = "thiserror", derive(thiserror::Error))]
#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub enum NonceEquationError {
    /// A committed nonce is not a valid secp256k1 point.
    #[cfg_attr(feature = "thiserror", error("invalid nonce commitment point"))]
    InvalidNoncePoint,
    /// A scalar is zero or is not below the curve order.
    #[cfg_attr(feature = "thiserror", error("non-canonical secp256k1 scalar"))]
    NonCanonicalScalar,
}

/// Check the partial-signature equation `s*G == R1 + b*R2 + c*X`.
///
/// `x` is the signer's registered key, whose coordinates were validated at registration; `r1` and
/// `r2` are the batch-committed nonces and are re-checked on-curve here because they arrive as
/// caller-supplied evidence.
///
/// Returns `Ok(false)` when the equation does not hold, and also for the negligible-probability
/// degenerate cases that make the check unevaluable (recovery failure, a sum at infinity, or a
/// base point whose x-coordinate is not a canonical scalar). `Err` means the inputs are malformed.
///
/// The check costs two `secp256k1_recover` syscalls and one point addition. It rearranges the
/// equation as `s*G - b*R2 == R1 + c*X` so that each side is one recovery:
/// ECDSA recovery over `(r, s_sig, h)` yields `r^-1 * (s_sig*R - h*G)` for the point `R` with
/// x-coordinate `r`, which produces `s*G - b*R2` from base `R2` and `c*X` from base `X`.
pub fn verify_partial_signature_equation(
    x: &SignerXy,
    r1: &SignerXy,
    r2: &SignerXy,
    b: &[u8; 32],
    c: &[u8; 32],
    s: &[u8; 32],
) -> Result<bool, NonceEquationError> {
    for scalar in [b, c, s] {
        if !secp256k1_scalar_is_valid_nonzero(scalar) {
            return Err(NonceEquationError::NonCanonicalScalar);
        }
    }

    let mut scratch = [0u8; 65];
    let r1_point: Affine = public_key_from_affine_xy(&mut scratch, &r1.0, &r1.1)
        .map_err(|_| NonceEquationError::InvalidNoncePoint)?
        .into();
    public_key_from_affine_xy(&mut scratch, &r2.0, &r2.1)
        .map_err(|_| NonceEquationError::InvalidNoncePoint)?;

    // Recovery reads `r` as a scalar, so a base point with x >= n cannot anchor the equation.
    if !secp256k1_scalar_is_valid_nonzero(&r2.0) || !secp256k1_scalar_is_valid_nonzero(&x.0) {
        return Ok(false);
    }

    // c*X from base X: s_sig = c*X.x, h = 0.
    let right_term = match recover_point(&x.0, &x.1, &mul_mod(c, &x.0), &[0u8; 32]) {
        Some(point) => point,
        None => return Ok(false),
    };

    // s*G - b*R2 from base R2: s_sig = -b*R2.x, h = -s*R2.x.
    let left = match recover_point(
        &r2.0,
        &r2.1,
        &negate_mod_n(&mul_mod(b, &r2.0)),
        &negate_mod_n(&mul_mod(s, &r2.0)),
    ) {
        Some(point) => point,
        None => return Ok(false),
    };

    let mut right_x = [0u8; 32];
    let mut right_y = [0u8; 32];
    right_x.copy_from_slice(&right_term[..32]);
    right_y.copy_from_slice(&right_term[32..]);
    let right_point = match affine_from_stored_secp_xy(&right_x, &right_y) {
        Ok(point) => point,
        Err(_) => return Ok(false),
    };

    // Variable-time add: every input is public on-chain evidence.
    let right = Jacobian::from_ge(&r1_point).add_ge_var(&right_point, None);
    if right.is_infinity() {
        return Ok(false);
    }
    let mut right = Affine::from_gej(&right);
    right.x.normalize_var();
    right.y.normalize_var();

    let mut sum_x = [0u8; 32];
    let mut sum_y = [0u8; 32];
    right.x.fill_b32(&mut sum_x);
    right.y.fill_b32(&mut sum_y);

    Ok(sum_x[..] == left[..32] && sum_y[..] == left[32..])
}

/// Recover `base_x^-1 * (ecdsa_s*Base - ecdsa_hash*G)` for the curve point `Base = (base_x, base_y)`.
fn recover_point(
    base_x: &[u8; 32],
    base_y: &[u8; 32],
    ecdsa_s: &[u8; 32],
    ecdsa_hash: &[u8; 32],
) -> Option<[u8; 64]> {
    let mut signature = [0u8; 64];
    signature[..32].copy_from_slice(base_x);
    signature[32..].copy_from_slice(ecdsa_s);
    let recovery_id = secp256k1_ecdsa_normalize_low_s(base_y[31] & 1, &mut signature).ok()?;
    Some(
        secp256k1_recover(ecdsa_hash, recovery_id, &signature)
            .ok()?
            .to_bytes(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use libsecp256k1::{curve::ECMultGenContext, PublicKey, PublicKeyFormat, SecretKey};
    use num_bigint::BigUint;

    const SECP256K1_ORDER: [u8; 32] = [
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFE, 0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B, 0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36,
        0x41, 0x41,
    ];

    fn scalar(value: u8) -> [u8; 32] {
        let mut out = [0u8; 32];
        out[31] = value;
        out
    }

    fn add_mod_n(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
        let order = BigUint::from_bytes_be(&SECP256K1_ORDER);
        let sum = (BigUint::from_bytes_be(a) + BigUint::from_bytes_be(b)) % order;
        let bytes = sum.to_bytes_be();
        let mut out = [0u8; 32];
        out[32 - bytes.len()..].copy_from_slice(&bytes);
        out
    }

    fn point_for_secret(secret: &[u8; 32]) -> SignerXy {
        let secret = SecretKey::parse(secret).expect("valid secret");
        let context = ECMultGenContext::new_boxed();
        let full = PublicKey::from_secret_key_with_context(&secret, &context).serialize();
        (
            full[1..33].try_into().unwrap(),
            full[33..65].try_into().unwrap(),
        )
    }

    /// An honest partial: `s = r1 + b*r2 + c*x`.
    fn transcript(
        r1_secret: &[u8; 32],
        r2_secret: &[u8; 32],
        x_secret: &[u8; 32],
        b: &[u8; 32],
        c: &[u8; 32],
    ) -> [u8; 32] {
        add_mod_n(
            r1_secret,
            &add_mod_n(&mul_mod(b, r2_secret), &mul_mod(c, x_secret)),
        )
    }

    struct Fixture {
        x: SignerXy,
        r1: SignerXy,
        r2: SignerXy,
        b: [u8; 32],
        c: [u8; 32],
        s: [u8; 32],
    }

    fn fixture(seed: u8, b: [u8; 32], c: [u8; 32]) -> Fixture {
        let x_secret = scalar(seed.wrapping_add(7).max(1));
        let r1_secret = scalar(seed.wrapping_add(11).max(1));
        let r2_secret = scalar(seed.wrapping_add(23).max(1));
        Fixture {
            x: point_for_secret(&x_secret),
            r1: point_for_secret(&r1_secret),
            r2: point_for_secret(&r2_secret),
            b,
            c,
            s: transcript(&r1_secret, &r2_secret, &x_secret, &b, &c),
        }
    }

    fn check(f: &Fixture) -> Result<bool, NonceEquationError> {
        verify_partial_signature_equation(&f.x, &f.r1, &f.r2, &f.b, &f.c, &f.s)
    }

    #[test]
    fn honest_partial_satisfies_the_equation() {
        for seed in 0..24u8 {
            let f = fixture(
                seed,
                scalar(seed.wrapping_add(3).max(1)),
                scalar(seed.max(1)),
            );
            assert_eq!(check(&f), Ok(true), "seed {seed}");
        }
    }

    #[test]
    fn large_challenge_scalars_verify() {
        let b = [0x7f; 32];
        let mut c = SECP256K1_ORDER;
        c[31] -= 1; // n - 1, the largest canonical scalar.
        let f = fixture(5, b, c);
        assert_eq!(check(&f), Ok(true));
    }

    #[test]
    fn perturbing_any_input_breaks_the_equation() {
        let base = fixture(3, scalar(17), scalar(29));

        let mut wrong_s = base.s;
        wrong_s[31] ^= 1;
        assert_eq!(
            verify_partial_signature_equation(
                &base.x, &base.r1, &base.r2, &base.b, &base.c, &wrong_s
            ),
            Ok(false)
        );

        let mut wrong_b = base.b;
        wrong_b[31] ^= 1;
        assert_eq!(
            verify_partial_signature_equation(
                &base.x, &base.r1, &base.r2, &wrong_b, &base.c, &base.s
            ),
            Ok(false)
        );

        let mut wrong_c = base.c;
        wrong_c[31] ^= 1;
        assert_eq!(
            verify_partial_signature_equation(
                &base.x, &base.r1, &base.r2, &base.b, &wrong_c, &base.s
            ),
            Ok(false)
        );

        let other = fixture(9, scalar(17), scalar(29));
        assert_eq!(
            verify_partial_signature_equation(
                &other.x, &base.r1, &base.r2, &base.b, &base.c, &base.s
            ),
            Ok(false)
        );
        assert_eq!(
            verify_partial_signature_equation(
                &base.x, &other.r1, &base.r2, &base.b, &base.c, &base.s
            ),
            Ok(false)
        );
        assert_eq!(
            verify_partial_signature_equation(
                &base.x, &base.r1, &other.r2, &base.b, &base.c, &base.s
            ),
            Ok(false)
        );
    }

    #[test]
    fn a_second_context_over_the_same_nonce_also_verifies() {
        // The offence itself: one committed (R1, R2), two verifying triples.
        let x_secret = scalar(41);
        let r1_secret = scalar(43);
        let r2_secret = scalar(47);
        let (x, r1, r2) = (
            point_for_secret(&x_secret),
            point_for_secret(&r1_secret),
            point_for_secret(&r2_secret),
        );

        let (b_a, c_a) = (scalar(3), scalar(5));
        let (b_b, c_b) = (scalar(7), scalar(11));
        let s_a = transcript(&r1_secret, &r2_secret, &x_secret, &b_a, &c_a);
        let s_b = transcript(&r1_secret, &r2_secret, &x_secret, &b_b, &c_b);

        assert_eq!(
            verify_partial_signature_equation(&x, &r1, &r2, &b_a, &c_a, &s_a),
            Ok(true)
        );
        assert_eq!(
            verify_partial_signature_equation(&x, &r1, &r2, &b_b, &c_b, &s_b),
            Ok(true)
        );
        // Transcripts do not cross over.
        assert_eq!(
            verify_partial_signature_equation(&x, &r1, &r2, &b_a, &c_a, &s_b),
            Ok(false)
        );
    }

    #[test]
    fn non_canonical_scalars_are_rejected() {
        let f = fixture(2, scalar(13), scalar(19));
        for bad in [[0u8; 32], SECP256K1_ORDER, [0xff; 32]] {
            assert_eq!(
                verify_partial_signature_equation(&f.x, &f.r1, &f.r2, &bad, &f.c, &f.s),
                Err(NonceEquationError::NonCanonicalScalar)
            );
            assert_eq!(
                verify_partial_signature_equation(&f.x, &f.r1, &f.r2, &f.b, &bad, &f.s),
                Err(NonceEquationError::NonCanonicalScalar)
            );
            assert_eq!(
                verify_partial_signature_equation(&f.x, &f.r1, &f.r2, &f.b, &f.c, &bad),
                Err(NonceEquationError::NonCanonicalScalar)
            );
        }
    }

    #[test]
    fn off_curve_nonce_points_are_rejected() {
        let f = fixture(4, scalar(21), scalar(31));

        let mut off_curve = f.r1;
        off_curve.1[31] ^= 1;
        assert_eq!(
            verify_partial_signature_equation(&f.x, &off_curve, &f.r2, &f.b, &f.c, &f.s),
            Err(NonceEquationError::InvalidNoncePoint)
        );

        let mut off_curve = f.r2;
        off_curve.1[31] ^= 1;
        assert_eq!(
            verify_partial_signature_equation(&f.x, &f.r1, &off_curve, &f.b, &f.c, &f.s),
            Err(NonceEquationError::InvalidNoncePoint)
        );

        let zero = ([0u8; 32], [0u8; 32]);
        assert_eq!(
            verify_partial_signature_equation(&f.x, &zero, &f.r2, &f.b, &f.c, &f.s),
            Err(NonceEquationError::InvalidNoncePoint)
        );
    }

    /// The `c*X` recovery passes a zero message hash; pin that the recovery path accepts it.
    #[test]
    fn zero_ecdsa_hash_recovers() {
        let x = point_for_secret(&scalar(33));
        let c = scalar(6);
        let recovered = recover_point(&x.0, &x.1, &mul_mod(&c, &x.0), &[0u8; 32])
            .expect("recovery with a zero message hash");

        // c*X computed independently.
        let expected = point_for_secret(&mul_mod(&c, &scalar(33)));
        assert_eq!(recovered[..32], expected.0[..]);
        assert_eq!(recovered[32..], expected.1[..]);
    }

    #[test]
    fn a_nonce_ground_to_cancel_the_key_term_is_unevaluable_not_a_panic() {
        // R1 = -(c*X) makes the right-hand sum the point at infinity.
        let x_secret = scalar(53);
        let c = scalar(4);
        let r1_secret = negate_mod_n(&mul_mod(&c, &x_secret));
        let r2_secret = scalar(59);
        let b = scalar(8);

        let f = Fixture {
            x: point_for_secret(&x_secret),
            r1: point_for_secret(&r1_secret),
            r2: point_for_secret(&r2_secret),
            b,
            c,
            s: transcript(&r1_secret, &r2_secret, &x_secret, &b, &c),
        };
        assert_eq!(check(&f), Ok(false));
    }

    #[test]
    fn degenerate_left_hand_side_does_not_panic() {
        // s*G == b*R2 makes the recovered left term the point at infinity, which recovery rejects.
        let x_secret = scalar(61);
        let r2_secret = scalar(67);
        let b = scalar(9);
        let s = mul_mod(&b, &r2_secret);

        let x = point_for_secret(&x_secret);
        let r1 = point_for_secret(&scalar(71));
        let r2 = point_for_secret(&r2_secret);
        assert_eq!(
            verify_partial_signature_equation(&x, &r1, &r2, &b, &scalar(3), &s),
            Ok(false)
        );
    }

    #[test]
    fn recovered_points_are_valid_curve_points() {
        let f = fixture(6, scalar(15), scalar(25));
        let recovered = recover_point(
            &f.r2.0,
            &f.r2.1,
            &negate_mod_n(&mul_mod(&f.b, &f.r2.0)),
            &negate_mod_n(&mul_mod(&f.s, &f.r2.0)),
        )
        .expect("recovery");

        let mut full = [0u8; 65];
        full[0] = 0x04;
        full[1..65].copy_from_slice(&recovered);
        assert!(PublicKey::parse_slice(&full, Some(PublicKeyFormat::Full)).is_ok());
    }
}
