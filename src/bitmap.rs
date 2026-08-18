//! EVM-compatible `uint256` bitmap operations and deterministic selection-group derivation.
//!
//! Pure, anchor-free. Moved verbatim from the Molpha program's `utils/bitmap.rs`
//! (`MolphaError` → [`AttestationError`]).

use ethnum::U256;
use solana_keccak_hasher::hashv;

use crate::error::AttestationError;

/// `keccak256("MOLPHA_SELECTION_DERIVE")` — EVM `NodeGroupBitmapLib.SELECTION_DOMAIN`.
const SELECTION_DOMAIN: [u8; 32] = [
    0x49, 0x28, 0x48, 0xfe, 0x5e, 0x85, 0xd4, 0xce, 0x22, 0x31, 0xd6, 0x93, 0xa5, 0x8f, 0x08, 0x20,
    0xa4, 0x05, 0x6e, 0x28, 0x22, 0xfe, 0x5d, 0xca, 0xd7, 0xc7, 0x56, 0xaf, 0xe0, 0x44, 0xb7, 0x0b,
];

/// Max Keccak-256 rounds (bounded compute); Solidity loop is unbounded.
const DERIVE_GROUP_BITMAP_MAX_ROUNDS: u64 = 65_536;

/// EVM `uint256` bitmap loaded from Solidity `bytes32` (big-endian).
#[inline]
pub fn bitmap_load(bytes: &[u8; 32]) -> U256 {
    U256::from_be_bytes(*bytes)
}

/// Serialize an EVM `uint256` bitmap to `bytes32` for storage / hashing.
#[inline]
pub fn bitmap_store(value: U256) -> [u8; 32] {
    value.to_be_bytes()
}

/// Solidity `uint256` layout: bit `pos` has weight `1 << pos`, `pos == 0` is the integer LSB.
#[inline]
pub fn bitmap_bit_set(bitmap: &[u8; 32], pos: usize) -> bool {
    debug_assert!(pos < 256);
    (bitmap_load(bitmap) >> pos) & U256::from(1u8) != U256::ZERO
}

#[inline]
pub fn bitmap_set_bit(bitmap: &mut [u8; 32], pos: usize) {
    debug_assert!(pos < 256);
    let mut v = bitmap_load(bitmap);
    v |= U256::from(1u8) << pos;
    *bitmap = bitmap_store(v);
}

#[inline]
pub fn bitmap_clear_bit(bitmap: &mut [u8; 32], pos: usize) {
    debug_assert!(pos < 256);
    let mut v = bitmap_load(bitmap);
    v &= !(U256::from(1u8) << pos);
    *bitmap = bitmap_store(v);
}

pub fn bitmap_popcount_evm(bitmap: &[u8; 32]) -> u32 {
    bitmap_load(bitmap).count_ones()
}

/// `sub ⊆ sup` when both are already loaded as `U256`.
#[inline]
pub fn bitmap_is_subset_u256(sub: U256, sup: U256) -> bool {
    (sub & !sup) == U256::ZERO
}

/// Reject signers with bits outside `[0, node_count)`.
pub fn validate_bitmap_upper_bits_clear_u256(
    bitmap: U256,
    node_count: u32,
) -> Result<(), AttestationError> {
    if node_count > 256 {
        return Err(AttestationError::InvalidSignersBitmap);
    }
    let mask = if node_count == 256 {
        U256::MAX
    } else {
        (U256::from(1u8) << node_count) - U256::from(1u8)
    };
    if (bitmap & !mask) != U256::ZERO {
        return Err(AttestationError::InvalidSignersBitmap);
    }
    Ok(())
}

/// Visit set bits in ascending order; returns the peeled bitmap (zero when fully consumed).
pub fn for_each_set_bit_u256<F, E>(mut bm: U256, mut f: F) -> Result<U256, E>
where
    F: FnMut(usize) -> Result<(), E>,
{
    while bm != U256::ZERO {
        let bit_pos = bm.trailing_zeros() as usize;
        bm &= bm - U256::from(1u8);
        f(bit_pos)?;
    }
    Ok(bm)
}

/// Bitmap **bit index** of the signer at 0-based rank `pos` when signers are ordered by ascending
/// bit index (same order as EVM `Validator.verify` combines pubkeys).
pub fn get_index(bitmap: &[u8; 32], pos: usize) -> Option<usize> {
    let mut bm = bitmap_load(bitmap);
    let mut rank = 0usize;
    while bm != U256::ZERO {
        let bit_pos = bm.trailing_zeros() as usize;
        if rank == pos {
            return Some(bit_pos);
        }
        bm &= bm - U256::from(1u8);
        rank += 1;
    }
    None
}

/// Iterate set bit positions in ascending order (EVM signer order).
pub fn for_each_set_bit<F>(bitmap: &[u8; 32], mut f: F)
where
    F: FnMut(usize),
{
    let mut bm = bitmap_load(bitmap);
    while bm != U256::ZERO {
        let bit_pos = bm.trailing_zeros() as usize;
        f(bit_pos);
        bm &= bm - U256::from(1u8);
    }
}

fn u256_be_from_u64(counter: u64) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[24..32].copy_from_slice(&counter.to_be_bytes());
    out
}

/// `keccak256(seed || SELECTION_DOMAIN || counter_be)` — uses `sol_keccak256` on BPF.
fn selection_hash_round(seed: &[u8; 32], counter: u64) -> [u8; 32] {
    let counter_word = u256_be_from_u64(counter);
    hashv(&[seed.as_ref(), &SELECTION_DOMAIN, &counter_word]).to_bytes()
}

#[inline]
fn full_mask_u256(node_count: u32) -> U256 {
    if node_count == 256 {
        U256::MAX
    } else {
        (U256::from(1u8) << node_count) - U256::from(1u8)
    }
}

/// Without-replacement sampling — port of EVM `_sampleWithoutReplacement`.
fn sample_without_replacement(
    seed: &[u8; 32],
    node_count: u32,
    group_size: u32,
) -> Result<U256, AttestationError> {
    let limit = (u64::from(u32::MAX) / u64::from(node_count)) * u64::from(node_count);
    let mut bitmap = U256::ZERO;
    let mut selected = 0u32;
    let mut counter = 0u64;

    while selected < group_size {
        if counter >= DERIVE_GROUP_BITMAP_MAX_ROUNDS {
            return Err(AttestationError::GroupBitmapDerivationFailed);
        }

        let digest = selection_hash_round(seed, counter);
        counter += 1;

        let mut word = bitmap_load(&digest);
        for _ in 0..8 {
            if selected >= group_size {
                break;
            }

            let limb = u32::try_from(word >> 224).unwrap_or(u32::MAX);
            word <<= 32;

            if u64::from(limb) < limit {
                let pos = (limb % node_count) as usize;
                let bit = U256::from(1u8) << pos;
                if (bitmap & bit) == U256::ZERO {
                    bitmap |= bit;
                    selected += 1;
                }
            }
        }
    }

    Ok(bitmap)
}

/// Port of `NodeGroupBitmapLib.derive` from the EVM reference.
pub fn derive_group_bitmap(
    seed: &[u8; 32],
    node_count: u32,
    group_size: u32,
) -> Result<[u8; 32], AttestationError> {
    if node_count == 0 {
        return Err(AttestationError::GroupBitmapDerivationFailed);
    }
    if node_count > 256 {
        return Err(AttestationError::GroupBitmapDerivationFailed);
    }
    if group_size > node_count {
        return Err(AttestationError::GroupBitmapDerivationFailed);
    }
    if group_size == 0 {
        return Ok([0u8; 32]);
    }
    if group_size == node_count {
        return Ok(bitmap_store(full_mask_u256(node_count)));
    }

    let bitmap = if group_size > node_count / 2 {
        let excluded = sample_without_replacement(seed, node_count, node_count - group_size)?;
        full_mask_u256(node_count) ^ excluded
    } else {
        sample_without_replacement(seed, node_count, group_size)?
    };

    Ok(bitmap_store(bitmap))
}

pub fn bitmap_is_subset(sub: &[u8; 32], sup: &[u8; 32]) -> bool {
    let sub = bitmap_load(sub);
    let sup = bitmap_load(sup);
    (sub & !sup) == U256::ZERO
}

/// Selection slot count: `min(node_count, signatures_required + redundancy_buffer)`.
#[inline]
pub fn effective_selection_size(
    signatures_required: u8,
    redundancy_buffer: u8,
    node_count: u32,
) -> u32 {
    u32::from(signatures_required)
        .saturating_add(u32::from(redundancy_buffer))
        .min(node_count)
}

pub fn validate_bitmap_upper_bits_clear(
    bitmap: &[u8; 32],
    node_count: u32,
) -> Result<(), AttestationError> {
    validate_bitmap_upper_bits_clear_u256(bitmap_load(bitmap), node_count)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_index_orders_signers_by_ascending_bit() {
        // EVM uint256 `7` => bits 0,1,2 set.
        let bm: [u8; 32] = [
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0x07,
        ];
        assert_eq!(get_index(&bm, 0), Some(0));
        assert_eq!(get_index(&bm, 1), Some(1));
        assert_eq!(get_index(&bm, 2), Some(2));
        assert_eq!(get_index(&bm, 3), None);
    }

    #[test]
    fn get_index_skips_gaps() {
        let mut bm = [0u8; 32];
        bitmap_set_bit(&mut bm, 5);
        bitmap_set_bit(&mut bm, 10);
        assert_eq!(get_index(&bm, 0), Some(5));
        assert_eq!(get_index(&bm, 1), Some(10));
        assert_eq!(get_index(&bm, 2), None);
    }

    #[test]
    fn validate_bitmap_upper_bits_clear_rejects_high_bits() {
        let mut bm = [0u8; 32];
        bitmap_set_bit(&mut bm, 10);
        assert!(validate_bitmap_upper_bits_clear(&bm, 8).is_err());
        assert!(validate_bitmap_upper_bits_clear(&bm, 11).is_ok());
    }

    #[test]
    fn u256_bit_ops_match_byte_layout() {
        let mut bm = [0u8; 32];
        bitmap_set_bit(&mut bm, 0);
        bitmap_set_bit(&mut bm, 7);
        bitmap_set_bit(&mut bm, 255);
        assert!(bitmap_bit_set(&bm, 0));
        assert!(bitmap_bit_set(&bm, 7));
        assert!(bitmap_bit_set(&bm, 255));
        assert!(!bitmap_bit_set(&bm, 1));
        assert_eq!(bitmap_popcount_evm(&bm), 3);
    }

    #[test]
    fn effective_selection_size_caps_at_node_count() {
        assert_eq!(effective_selection_size(8, 2, 8), 8);
        assert_eq!(effective_selection_size(5, 2, 8), 7);
        assert_eq!(effective_selection_size(10, 2, 8), 8);
    }

    #[test]
    fn derive_group_bitmap_matches_evm_reference_vectors() {
        let seed = [0x11u8; 32];
        let cases: &[(u32, u32, &str)] = &[
            (
                8,
                3,
                "0000000000000000000000000000000000000000000000000000000000000038",
            ),
            (
                10,
                7,
                "00000000000000000000000000000000000000000000000000000000000003d3",
            ),
            (
                16,
                5,
                "0000000000000000000000000000000000000000000000000000000000002c30",
            ),
            (
                32,
                20,
                "00000000000000000000000000000000000000000000000000000000d7ddb3a1",
            ),
        ];
        for (node_count, group_size, want_hex) in cases {
            let got = derive_group_bitmap(&seed, *node_count, *group_size).unwrap();
            let want = hex_to_bytes32(want_hex);
            assert_eq!(got, want, "n={node_count} g={group_size}");
        }
    }

    #[test]
    fn derive_group_bitmap_complement_path_matches_direct_sample() {
        let seed = [0x22u8; 32];
        let node_count = 10u32;
        let group_size = 7u32;
        let direct = derive_group_bitmap(&seed, node_count, group_size).unwrap();
        let excluded = derive_group_bitmap(&seed, node_count, node_count - group_size).unwrap();
        let mut full = [0u8; 32];
        for pos in 0..node_count as usize {
            bitmap_set_bit(&mut full, pos);
        }
        let excluded_bm = bitmap_load(&excluded);
        let complement = bitmap_store(bitmap_load(&full) ^ excluded_bm);
        assert_eq!(direct, complement);
    }

    fn hex_to_bytes32(hex: &str) -> [u8; 32] {
        let hex = hex.strip_prefix("0x").unwrap_or(hex);
        let mut out = [0u8; 32];
        for (i, chunk) in hex.as_bytes().chunks(2).enumerate() {
            let s = std::str::from_utf8(chunk).unwrap();
            out[i] = u8::from_str_radix(s, 16).unwrap();
        }
        out
    }
}
