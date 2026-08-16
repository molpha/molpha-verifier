//! secp256k1 scalar arithmetic and the EVM Schnorr→ECDSA recovery trick.
//!
//! Pure, anchor-free. Moved verbatim from the Molpha program's `utils/schnorr.rs`
//! (`MolphaError` → [`DataUpdateError`]).

use solana_keccak_hasher::hashv;

use crate::error::DataUpdateError;

const SECP256K1_ORDER: [u8; 32] = [
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
    0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B, 0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41,
];

/// secp256k1 curve order / 2 (rounded down).
const SECP256K1_ORDER_HALF: [u8; 32] = [
    0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0x5D, 0x57, 0x6E, 0x73, 0x57, 0xA4, 0x50, 0x1D, 0xDF, 0xE9, 0x2F, 0x46, 0x68, 0x1B, 0x20, 0xA0,
];

const SECP256K1_ORDER_MINUS_TWO: [u8; 32] = [
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
    0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B, 0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x3F,
];

// secp256k1 curve order n, little-endian u64 limbs (least significant limb first).
const SECP256K1_ORDER_LIMBS_LE: [u64; 4] = [
    0xBFD25E8CD0364141,
    0xBAAEDCE6AF48A03B,
    0xFFFFFFFFFFFFFFFE,
    0xFFFFFFFFFFFFFFFF,
];

// mu = floor(2^512 / n), little-endian u64 limbs.
//
// Derived from:
//   n  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
//   mu = floor(2^512 / n)
const SECP256K1_ORDER_BARRETT_MU_LIMBS_LE: [u64; 5] = [
    0x402DA1732FC9BEC0,
    0x4551231950B75FC4,
    0x0000000000000001,
    0x0000000000000000,
    0x0000000000000001,
];

fn cmp_be(a: &[u8; 32], b: &[u8; 32]) -> core::cmp::Ordering {
    for i in 0..32 {
        if a[i] < b[i] {
            return core::cmp::Ordering::Less;
        }
        if a[i] > b[i] {
            return core::cmp::Ordering::Greater;
        }
    }
    core::cmp::Ordering::Equal
}

pub fn secp256k1_scalar_is_valid_nonzero(x: &[u8; 32]) -> bool {
    !is_zero(x) && cmp_be(x, &SECP256K1_ORDER) == core::cmp::Ordering::Less
}

/// Normalize an ECDSA signature to "low-s" form.
///
/// Some secp256k1 recovery implementations reject high-s signatures.
/// If `s > n/2`, converts `(r, s)` to `(r, n-s)` and flips `recovery_id` parity bit.
pub fn secp256k1_ecdsa_normalize_low_s(
    mut recovery_id: u8,
    signature_64: &mut [u8; 64],
) -> Result<u8, DataUpdateError> {
    let mut s = [0u8; 32];
    s.copy_from_slice(&signature_64[32..64]);

    if cmp_be(&s, &SECP256K1_ORDER_HALF) == core::cmp::Ordering::Greater {
        let new_s = sub_be(&SECP256K1_ORDER, &s);
        signature_64[32..64].copy_from_slice(&new_s);
        recovery_id ^= 1;
    }

    // Ensure non-zero `s` after normalization.
    if signature_64[32..64].iter().all(|b| *b == 0) {
        return Err(DataUpdateError::InvalidSignature);
    }

    Ok(recovery_id)
}

fn sub_be(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut borrow = 0i16;
    for i in (0..32).rev() {
        let diff = a[i] as i16 - b[i] as i16 - borrow;
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

#[inline]
fn mod_reduce_once(mut x: [u8; 32]) -> [u8; 32] {
    if cmp_be(&x, &SECP256K1_ORDER) != core::cmp::Ordering::Less {
        x = sub_be(&x, &SECP256K1_ORDER);
    }
    x
}

/// Reduce a 32-byte big-endian integer modulo secp256k1 curve order \(n\).
///
/// This is used to port EVM `uint256(...) % Q()` semantics for challenges.
pub fn secp256k1_scalar_reduce_be(x: [u8; 32]) -> [u8; 32] {
    mod_reduce_once(x)
}

fn is_zero(x: &[u8; 32]) -> bool {
    x.iter().all(|b| *b == 0)
}

fn get_bit_be(x: &[u8; 32], bit_index: usize) -> u8 {
    // Bit ordering for a 256-bit **big-endian** integer as used by EVM `uint256`:
    // - `bit_index == 0` is the most significant bit (byte 0, bit 7)
    // - `bit_index == 255` is the least significant bit (byte 31, bit 0)
    debug_assert!(bit_index < 256);
    let byte = bit_index / 8;
    let bit = 7 - (bit_index % 8);
    (x[byte] >> bit) & 1
}

pub fn mul_mod(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    mul_mod_n_barrett(a, b)
}

/// EVM/Solidity `mulmod(a, b, Q)` for 256-bit values, where `Q` is secp256k1 order.
///
/// This is used to match `mulmod(..., LibSecp256k1.Q())` semantics exactly.
fn mod_pow(base: &[u8; 32], exponent: &[u8; 32]) -> [u8; 32] {
    let exp = mod_reduce_once(*exponent);
    let base_red = mod_reduce_once(*base);

    let mut result = [0u8; 32];
    let mut seen = false;

    for i in 0..256 {
        let bit = get_bit_be(&exp, i);
        if bit == 0 && !seen {
            continue;
        }

        if !seen {
            result = base_red;
            seen = true;
            continue;
        }

        result = mul_mod(&result, &result);
        if bit == 1 {
            result = mul_mod(&result, &base_red);
        }
    }

    if !seen {
        // `exp == 0` ⇒ x^0 == 1 (mod n)
        result[31] = 1;
    }

    result
}

pub fn inv_mod(a: &[u8; 32]) -> Option<[u8; 32]> {
    if is_zero(a) {
        return None;
    }
    Some(mod_pow(a, &SECP256K1_ORDER_MINUS_TWO))
}

#[inline]
fn be32_to_limbs_le(x: &[u8; 32]) -> [u64; 4] {
    let mut out = [0u64; 4];
    for (i, limb) in out.iter_mut().enumerate() {
        let start = 32 - (i + 1) * 8;
        *limb = u64::from_be_bytes(x[start..start + 8].try_into().unwrap());
    }
    out
}

#[inline]
fn limbs_le_to_be32(x: &[u64; 4]) -> [u8; 32] {
    let mut out = [0u8; 32];
    for i in 0..4 {
        let bytes = x[3 - i].to_be_bytes();
        out[i * 8..(i + 1) * 8].copy_from_slice(&bytes);
    }
    out
}

#[inline]
fn cmp_limbs_le_4(a: &[u64; 4], b: &[u64; 4]) -> core::cmp::Ordering {
    for i in (0..4).rev() {
        if a[i] < b[i] {
            return core::cmp::Ordering::Less;
        }
        if a[i] > b[i] {
            return core::cmp::Ordering::Greater;
        }
    }
    core::cmp::Ordering::Equal
}

#[inline]
fn sub_limbs_le_4(mut a: [u64; 4], b: &[u64; 4]) -> [u64; 4] {
    let mut borrow: u64 = 0;
    for i in 0..4 {
        let (r1, b1) = a[i].overflowing_sub(b[i]);
        let (r2, b2) = r1.overflowing_sub(borrow);
        a[i] = r2;
        borrow = (b1 as u64) | (b2 as u64);
    }
    a
}

#[inline]
fn reduce_mod_n_le(x: [u64; 4]) -> [u64; 4] {
    if cmp_limbs_le_4(&x, &SECP256K1_ORDER_LIMBS_LE) != core::cmp::Ordering::Less {
        sub_limbs_le_4(x, &SECP256K1_ORDER_LIMBS_LE)
    } else {
        x
    }
}

#[inline]
fn mul_4x4(a: &[u64; 4], b: &[u64; 4]) -> [u64; 8] {
    let mut out = [0u64; 8];
    for i in 0..4 {
        let mut carry: u64 = 0;
        for j in 0..4 {
            let t = (a[i] as u128) * (b[j] as u128) + (out[i + j] as u128) + (carry as u128);
            out[i + j] = t as u64;
            carry = (t >> 64) as u64;
        }
        out[i + 4] = carry;
    }
    out
}

#[inline]
fn mul_limbs(a: &[u64], b: &[u64], out: &mut [u64]) {
    debug_assert!(out.len() >= a.len() + b.len());
    out.fill(0);
    for (i, &ai) in a.iter().enumerate() {
        let mut carry: u64 = 0;
        for (j, &bj) in b.iter().enumerate() {
            let idx = i + j;
            let t = (ai as u128) * (bj as u128) + (out[idx] as u128) + (carry as u128);
            out[idx] = t as u64;
            carry = (t >> 64) as u64;
        }
        out[i + b.len()] = carry;
    }
}

#[inline]
fn shr_255_from_512(x: &[u64; 8]) -> [u64; 5] {
    // q1 = floor(x / 2^255)
    let mut out = [0u64; 5];
    // shift right by 255 = 3*64 + 63
    let lo = 3usize;
    let shift = 63u32;
    for i in 0..5 {
        let a = if lo + i < 8 { x[lo + i] } else { 0 };
        let b = if lo + i + 1 < 8 { x[lo + i + 1] } else { 0 };
        out[i] = (a >> shift) | (b << (64 - shift));
    }
    out
}

#[inline]
fn take_low_257_bits(x: &[u64; 8]) -> [u64; 5] {
    // r1 = x mod 2^257 (low 257 bits)
    let mut out = [0u64; 5];
    out[0] = x[0];
    out[1] = x[1];
    out[2] = x[2];
    out[3] = x[3];
    out[4] = x[4] & 1;
    out
}

#[inline]
fn barrett_reduce_mod_n(x: &[u64; 8]) -> [u64; 4] {
    // k = 256 bits, modulus < 2^k.
    // q1 = floor(x / 2^(k-1)) = x >> 255   (<= 257 bits)
    let q1 = shr_255_from_512(x);

    // q2 = q1 * mu (<= 514 bits)
    let mut q2 = [0u64; 10];
    mul_limbs(&q1, &SECP256K1_ORDER_BARRETT_MU_LIMBS_LE, &mut q2);

    // q3 = floor(q2 / 2^(k+1)) = q2 >> 257   (<= 257 bits)
    // shift right by 257 = 4*64 + 1
    let mut q3 = [0u64; 5];
    for i in 0..5 {
        let a = if 4 + i < 10 { q2[4 + i] } else { 0 };
        let b = if 4 + i + 1 < 10 { q2[4 + i + 1] } else { 0 };
        q3[i] = (a >> 1) | (b << 63);
    }

    // r1 = x mod 2^(k+1)
    let r1 = take_low_257_bits(x);

    // r2 = (q3 * n) mod 2^(k+1)
    let mut q3n = [0u64; 9];
    mul_limbs(&q3, &SECP256K1_ORDER_LIMBS_LE, &mut q3n);
    let mut r2 = [0u64; 5];
    r2[0] = q3n[0];
    r2[1] = q3n[1];
    r2[2] = q3n[2];
    r2[3] = q3n[3];
    r2[4] = q3n[4] & 1;

    // r = (r1 - r2) mod 2^(k+1)
    let mut r = r1;
    let mut borrow: u64 = 0;
    for i in 0..5 {
        let (t1, b1) = r[i].overflowing_sub(r2[i]);
        let (t2, b2) = t1.overflowing_sub(borrow);
        r[i] = t2;
        borrow = (b1 as u64) | (b2 as u64);
    }
    // If underflow, add 2^(k+1) which is a no-op in mod 2^(k+1) arithmetic (already wrapped).
    // Ensure top limb stays 1-bit.
    r[4] &= 1;

    // Final correction: while r >= n, r -= n. At most 2 iterations for this setup.
    let mut r4 = [r[0], r[1], r[2], r[3]];
    // If r has the 257th bit set, it's definitely >= n (since n < 2^256).
    if r[4] != 0 {
        // subtract n once, borrowing from the top bit.
        r4 = sub_limbs_le_4(r4, &SECP256K1_ORDER_LIMBS_LE);
    }
    // Now r < 2^256, compare as 256-bit.
    if cmp_limbs_le_4(&r4, &SECP256K1_ORDER_LIMBS_LE) != core::cmp::Ordering::Less {
        r4 = sub_limbs_le_4(r4, &SECP256K1_ORDER_LIMBS_LE);
    }
    r4
}

pub fn mul_mod_n_barrett(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let a_le = reduce_mod_n_le(be32_to_limbs_le(&mod_reduce_once(*a)));
    let b_le = reduce_mod_n_le(be32_to_limbs_le(&mod_reduce_once(*b)));
    let prod = mul_4x4(&a_le, &b_le);
    let r_le = barrett_reduce_mod_n(&prod);
    limbs_le_to_be32(&r_le)
}

pub fn evm_schnorr_ecdsa_inputs(
    pubkey_compressed: &[u8; 33],
    msg_hash: &[u8; 32],
    signature: &[u8; 32],
    commitment: &[u8; 20],
) -> core::result::Result<(u8, [u8; 64], [u8; 32]), DataUpdateError> {
    let parity_prefix = pubkey_compressed[0];
    if parity_prefix != 0x02 && parity_prefix != 0x03 {
        return Err(DataUpdateError::InvalidSignature);
    }

    let recovery_id = parity_prefix & 1;

    let mut px = [0u8; 32];
    px.copy_from_slice(&pubkey_compressed[1..]);
    let px_mod_n = mod_reduce_once(px);
    if is_zero(&px_mod_n) {
        return Err(DataUpdateError::InvalidSignature);
    }

    let challenge_hash = hashv(&[
        px.as_slice(),
        &[recovery_id],
        msg_hash.as_slice(),
        commitment.as_slice(),
    ])
    .to_bytes();
    let challenge = mod_reduce_once(challenge_hash);

    let sig_red = mod_reduce_once(*signature);
    let msg_mul = mul_mod(&sig_red, &px_mod_n);
    // Solidity `unchecked { msgHash = Q - mulmod(...) }` (no special-case for zero).
    let e_ecdsa = sub_be(&SECP256K1_ORDER, &msg_mul);
    let ecdsa_s_mul = mul_mod(&challenge, &px_mod_n);
    let mut s_ecdsa = sub_be(&SECP256K1_ORDER, &ecdsa_s_mul);
    if is_zero(&s_ecdsa) {
        return Err(DataUpdateError::InvalidSignature);
    }

    // Ethereum `ecrecover` accepts malleable "high-s" signatures, but Solana's
    // `secp256k1_recover` implementation rejects non-canonical ECDSA `s` values.
    // Normalize to low-S (`s <= n/2`) and flip the recovery id (0/1), matching
    // standard ECDSA canonicalization used by secp256k1 libraries.
    let mut recovery_id = recovery_id;
    if cmp_be(&s_ecdsa, &SECP256K1_ORDER_HALF) == core::cmp::Ordering::Greater {
        s_ecdsa = sub_be(&SECP256K1_ORDER, &s_ecdsa);
        recovery_id ^= 1;
    }

    let mut ecdsa_signature = [0u8; 64];
    // Solidity passes `r` as the aggregate pubkey X coordinate (`uint256`), not `X mod Q`.
    ecdsa_signature[..32].copy_from_slice(&px);
    ecdsa_signature[32..].copy_from_slice(&s_ecdsa);

    Ok((recovery_id, ecdsa_signature, e_ecdsa))
}

pub fn eth_address_from_uncompressed_pubkey(uncompressed_xy: [u8; 64]) -> [u8; 20] {
    let digest = hashv(&[&uncompressed_xy]).to_bytes();
    let mut out = [0u8; 20];
    out.copy_from_slice(&digest[12..32]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use libsecp256k1::{PublicKey, PublicKeyFormat};
    use num_bigint::BigUint;
    use solana_secp256k1_recover::secp256k1_recover;

    fn be32_to_big(x: &[u8; 32]) -> BigUint {
        BigUint::from_bytes_be(x)
    }

    fn big_to_be32(x: BigUint) -> [u8; 32] {
        let bytes = x.to_bytes_be();
        assert!(bytes.len() <= 32);
        let mut out = [0u8; 32];
        out[32 - bytes.len()..].copy_from_slice(&bytes);
        out
    }

    fn mul_mod_bigint(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
        let n = be32_to_big(&SECP256K1_ORDER);
        let a = be32_to_big(a);
        let b = be32_to_big(b);
        let rem = (&a * &b) % &n;
        big_to_be32(rem)
    }

    fn mod_pow_naive_reference(base: &[u8; 32], exponent: &[u8; 32]) -> [u8; 32] {
        let exp = mod_reduce_once(*exponent);
        let base_red = mod_reduce_once(*base);
        let mut result = [0u8; 32];
        result[31] = 1;
        for i in 0..256 {
            result = mul_mod(&result, &result);
            if get_bit_be(&exp, i) == 1 {
                result = mul_mod(&result, &base_red);
            }
        }
        result
    }

    #[test]
    fn mod_pow_matches_naive_reference() {
        let mut base = [0u8; 32];
        base[31] = 28;

        for e in [1u32, 2, 3, 5, 6, 10, 100, 0] {
            let mut exp = [0u8; 32];
            if e != 0 {
                exp[31] = e as u8;
                if e > 255 {
                    exp[30] = (e >> 8) as u8;
                }
            }
            let expected = mod_pow_naive_reference(&base, &exp);
            let got = mod_pow(&base, &exp);
            assert_eq!(got, expected, "mod_pow mismatch for e={e}");
        }

        let mut a = [0u8; 32];
        a[31] = 3;
        assert_eq!(
            mod_pow(&a, &SECP256K1_ORDER_MINUS_TWO),
            mod_pow_naive_reference(&a, &SECP256K1_ORDER_MINUS_TWO),
        );
    }

    #[test]
    fn mod_pow_matches_bigint_small_exponents() {
        let n = be32_to_big(&SECP256K1_ORDER);
        let mut base = [0u8; 32];
        base[31] = 28;

        for e in [1u32, 2, 3, 5, 6, 10, 100] {
            let mut exp = [0u8; 32];
            exp[31] = e as u8;
            if e > 255 {
                exp[30] = (e >> 8) as u8;
            }
            let expected = big_to_be32(be32_to_big(&base).modpow(&BigUint::from(e), &n));
            let got = mod_pow(&base, &exp);
            assert_eq!(got, expected, "mod_pow mismatch for e={e}");
        }
    }

    #[test]
    fn inv_mod_for_three() {
        let mut a = [0u8; 32];
        a[31] = 3;
        let inv = inv_mod(&a).expect("nonzero scalar");
        let product = mul_mod(&a, &inv);
        assert_eq!(product[31], 1);
        assert!(product[..31].iter().all(|b| *b == 0));
    }

    #[test]
    fn mul_mod_matches_crypto_bigint_random() {
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        for i in 0u16..4096u16 {
            a[31] = i as u8;
            a[30] = (i >> 8) as u8;
            a[15] = (i.wrapping_mul(17)) as u8;
            b[31] = i.wrapping_mul(3) as u8;
            b[16] = i.wrapping_mul(5) as u8;
            b[1] = (i >> 4) as u8;
            let expected = mul_mod_bigint(&a, &b);
            let got = mul_mod(&a, &b);
            assert_eq!(got, expected, "mul_mod mismatch at i={i}");
        }
    }

    #[test]
    fn mul_mod_matches_crypto_bigint_fixture_vector() {
        // Aggregated pubkey x (signers 1..3) from `tests/instructions/verify-answer.test.ts` fixture.
        let px: [u8; 32] = [
            0x34, 0x62, 0x45, 0x12, 0x96, 0x14, 0xb5, 0xb4, 0x4e, 0xca, 0x16, 0x4c, 0x25, 0xc8,
            0x86, 0x01, 0x09, 0xa2, 0xec, 0xac, 0x8c, 0x9a, 0xdf, 0xd9, 0x0d, 0x9d, 0x1d, 0x8f,
            0x4f, 0x78, 0x43, 0xf4,
        ];
        let s: [u8; 32] = [
            0x36, 0x72, 0x88, 0xbf, 0x1b, 0xbd, 0xa4, 0xcd, 0x58, 0x44, 0x79, 0x32, 0x0c, 0x9e,
            0x96, 0xa2, 0xfb, 0xe8, 0x6f, 0x76, 0xa8, 0x84, 0x63, 0xc3, 0x6c, 0xa8, 0x27, 0x03,
            0x01, 0x67, 0xc9, 0x51,
        ];

        let px_mod_n = mod_reduce_once(px);
        let sig_red = mod_reduce_once(s);
        let py_q = BigUint::parse_bytes(
            b"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141",
            16,
        )
        .expect("valid hex");
        let n_from_const = be32_to_big(&SECP256K1_ORDER);
        assert_eq!(n_from_const, py_q);

        let expected = mul_mod_bigint(&sig_red, &px_mod_n);
        let got = mul_mod(&sig_red, &px_mod_n);
        assert_eq!(got, expected);
        assert_eq!(got[0], 0x27);
    }

    #[test]
    fn evm_schnorr_trick_recovers_commitment_for_verify_answer_fixture_vector() {
        /// Must match `crates/molpha-verifier/src/message.rs`.
        const MESSAGE_PREFIX: [u8; 32] = [
            0xa7, 0x55, 0x23, 0xa2, 0xab, 0x7b, 0x71, 0x8d, 0x9c, 0xff, 0xd2, 0xfa, 0x97, 0xed,
            0x06, 0x9f, 0xc1, 0x21, 0x84, 0xea, 0xbe, 0xe7, 0xd5, 0x07, 0x85, 0x4d, 0x09, 0x22,
            0xf7, 0x0e, 0x7f, 0xe7,
        ];

        // Compressed pubkeys for registered nodes 1..3 from `tests/instructions/verify-answer.test.ts`.
        let pk1: [u8; 33] = [
            0x03, 0xc0, 0x95, 0x27, 0xe9, 0x78, 0xf6, 0xea, 0x69, 0xf0, 0xc6, 0xb7, 0xac, 0x0f,
            0xb6, 0x3a, 0xd0, 0x81, 0xa8, 0xa2, 0x91, 0x15, 0x1c, 0x5a, 0x0b, 0x11, 0x5c, 0xce,
            0x43, 0x57, 0x51, 0xbe, 0x7d,
        ];
        let pk2: [u8; 33] = [
            0x02, 0x64, 0xa7, 0x27, 0x04, 0xf3, 0x9f, 0x8d, 0xd1, 0x7f, 0x20, 0xd7, 0x1c, 0x5b,
            0x21, 0xf3, 0x7b, 0x58, 0x52, 0x65, 0x6b, 0xc0, 0x55, 0x54, 0x42, 0xbf, 0x72, 0x72,
            0x22, 0xf2, 0x9d, 0x7e, 0x58,
        ];
        let pk3: [u8; 33] = [
            0x02, 0x75, 0xae, 0x1e, 0x3d, 0xac, 0x00, 0xeb, 0x7d, 0xf0, 0x2e, 0x9f, 0xe8, 0xd9,
            0x70, 0x9c, 0x8a, 0x2c, 0x09, 0xa1, 0x1e, 0xd4, 0xf7, 0xd9, 0xaa, 0x46, 0xa7, 0xde,
            0xa6, 0xcf, 0x37, 0x6d, 0x7f,
        ];

        let p1 = PublicKey::parse_slice(&pk1, Some(PublicKeyFormat::Compressed)).expect("pk1");
        let p2 = PublicKey::parse_slice(&pk2, Some(PublicKeyFormat::Compressed)).expect("pk2");
        let p3 = PublicKey::parse_slice(&pk3, Some(PublicKeyFormat::Compressed)).expect("pk3");
        let coalition = PublicKey::combine(&[p1, p2, p3]).expect("combine");
        let coalition_compressed = coalition.serialize_compressed();

        let source_id: [u8; 32] = [
            0x6a, 0x6f, 0x62, 0x2d, 0x65, 0x78, 0x74, 0x72, 0x61, 0x63, 0x74, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
        ];
        let registry_version = 42u32;
        let signatures_required = 3u32;

        // EVM bitmap integer `7` => nodes {1,2,3} => bits 0..2 set in EVM uint256 layout.
        let signers_bitmap: [u8; 32] = [
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x07,
        ];
        let value_bytes32: [u8; 32] = [
            0x76, 0x61, 0x6c, 0x2d, 0x65, 0x78, 0x74, 0x72, 0x61, 0x63, 0x74, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
        ];
        let timestamp = 1_700_001_234u64;

        let message_hash = hashv(&[
            MESSAGE_PREFIX.as_slice(),
            source_id.as_slice(),
            registry_version.to_be_bytes().as_slice(),
            signatures_required.to_be_bytes().as_slice(),
            signers_bitmap.as_slice(),
            value_bytes32.as_slice(),
            timestamp.to_be_bytes().as_slice(),
        ])
        .to_bytes();

        let s: [u8; 32] = [
            0x6c, 0xf2, 0xe6, 0x80, 0xd7, 0xde, 0x65, 0x00, 0x72, 0xec, 0xef, 0x9d, 0x07, 0x32,
            0xcd, 0x07, 0x8f, 0x68, 0x10, 0x0b, 0x6f, 0xf5, 0x31, 0x9f, 0xfd, 0x55, 0xb3, 0x19,
            0x92, 0x52, 0x1c, 0x62,
        ];
        let rx: [u8; 32] = [
            0xf0, 0x1d, 0x6b, 0x90, 0x18, 0xab, 0x42, 0x1d, 0xd4, 0x10, 0x40, 0x4c, 0xb8, 0x69,
            0x07, 0x20, 0x65, 0x52, 0x2b, 0xf8, 0x57, 0x34, 0x00, 0x8f, 0x10, 0x5c, 0xf3, 0x85,
            0xa0, 0x23, 0xa8, 0x0f,
        ];
        let ry_parity = 1u8;

        let mut r_compressed = [0u8; 33];
        r_compressed[0] = if ry_parity == 0 { 0x02 } else { 0x03 };
        r_compressed[1..].copy_from_slice(&rx);
        let r_point =
            PublicKey::parse_slice(&r_compressed, Some(PublicKeyFormat::Compressed)).expect("R");
        let r_uncompressed = r_point.serialize();
        let mut r_xy = [0u8; 64];
        r_xy.copy_from_slice(&r_uncompressed[1..65]);
        let commitment = eth_address_from_uncompressed_pubkey(r_xy);

        let (recovery_id, ecdsa_signature, ecdsa_hash) =
            evm_schnorr_ecdsa_inputs(&coalition_compressed, &message_hash, &s, &commitment)
                .expect("inputs");

        let recovered =
            secp256k1_recover(&ecdsa_hash, recovery_id, &ecdsa_signature).expect("recover");
        let recovered_addr = eth_address_from_uncompressed_pubkey(recovered.to_bytes());

        assert_eq!(recovered_addr, commitment);
    }
}
