//! Property-based tests for pure verification primitives.

mod fixtures;

use ethnum::U256;
use libsecp256k1::PublicKey;
use molpha_verifier::{
    bitmap::{
        bitmap_bit_set, bitmap_clear_bit, bitmap_is_subset, bitmap_is_subset_u256, bitmap_load,
        bitmap_popcount, bitmap_set_bit, bitmap_store, derive_group_bitmap,
        effective_selection_size, for_each_set_bit, validate_bitmap_upper_bits_clear,
    },
    coalition::{CoalitionAccumulator, public_key_from_affine_xy},
    message::compute_message_hash,
    payload::{AttestationPayload, SchnorrSignature},
    scalar::{
        mul_mod, secp256k1_ecdsa_normalize_low_s, secp256k1_scalar_is_valid_nonzero,
        secp256k1_scalar_reduce_be,
    },
    selection::derive_selection_bitmap,
    verify::{reconstruct_coalition_key, SignerXy},
};
use num_bigint::BigUint;
use proptest::prelude::*;

const SECP256K1_ORDER: [u8; 32] = [
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
    0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B, 0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41,
];

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
    let rem = (&be32_to_big(a) * &be32_to_big(b)) % &n;
    big_to_be32(rem)
}

fn arb_fixture_pubkey_subset() -> impl Strategy<Value = Vec<PublicKey>> {
    prop::collection::btree_set(0usize..12, 1..=12).prop_map(|indices| {
        let mut scratch = [0u8; 65];
        indices
            .into_iter()
            .map(|i| {
                let (x, y) = fixtures::PUBKEYS[i];
                public_key_from_affine_xy(&mut scratch, &x, &y).unwrap()
            })
            .collect()
    })
}

fn pubkey_to_xy(pk: &PublicKey) -> SignerXy {
    let full = pk.serialize();
    let x: [u8; 32] = full[1..33].try_into().unwrap();
    let y: [u8; 32] = full[33..65].try_into().unwrap();
    (x, y)
}

fn popcount_manual(bitmap: &[u8; 32]) -> u32 {
    let mut count = 0u32;
    for_each_set_bit(bitmap, |_| count += 1);
    count
}

fn bits_in_range(bitmap: &[u8; 32], node_count: u32) -> bool {
    let bm = bitmap_load(bitmap);
    let mask = if node_count == 256 {
        U256::MAX
    } else {
        (U256::from(1u8) << node_count) - U256::from(1u8)
    };
    (bm & !mask) == U256::ZERO
}

fn full_mask_bytes(node_count: u32) -> [u8; 32] {
    let mask = if node_count == 256 {
        U256::MAX
    } else {
        (U256::from(1u8) << node_count) - U256::from(1u8)
    };
    bitmap_store(mask)
}

fn arb_attestation_payload() -> impl Strategy<Value = AttestationPayload> {
    (
        any::<[u8; 32]>(),
        any::<[u8; 32]>(),
        any::<u32>(),
        any::<u8>(),
        any::<u64>(),
    )
        .prop_map(
            |(value, source_id, registry_version, signatures_required, canonical_timestamp)| {
                AttestationPayload {
                    value,
                    source_id,
                    registry_version,
                    signatures_required,
                    canonical_timestamp,
                }
            },
        )
}

fn arb_schnorr_signature() -> impl Strategy<Value = SchnorrSignature> {
    (any::<[u8; 32]>(), any::<[u8; 20]>(), any::<[u8; 32]>()).prop_map(
        |(agg_sig_s, commitment, signers_bitmap)| SchnorrSignature {
            agg_sig_s,
            commitment,
            signers_bitmap,
        },
    )
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn bitmap_store_load_roundtrip(bytes in any::<[u8; 32]>()) {
        let loaded = bitmap_load(&bytes);
        prop_assert_eq!(bitmap_store(loaded), bytes);
    }

    #[test]
    fn bitmap_set_and_clear_bit(pos in 0usize..256) {
        let mut bm = [0u8; 32];
        bitmap_set_bit(&mut bm, pos);
        prop_assert!(bitmap_bit_set(&bm, pos));
        bitmap_clear_bit(&mut bm, pos);
        prop_assert!(!bitmap_bit_set(&bm, pos));
    }

    #[test]
    fn bitmap_popcount_matches_manual_iteration(bytes in any::<[u8; 32]>()) {
        prop_assert_eq!(bitmap_popcount(&bytes), popcount_manual(&bytes));
    }

    #[test]
    fn bitmap_is_subset_matches_u256_semantics(
        sub in any::<[u8; 32]>(),
        sup in any::<[u8; 32]>(),
    ) {
        let sub_u = bitmap_load(&sub);
        let sup_u = bitmap_load(&sup);
        prop_assert_eq!(
            bitmap_is_subset(&sub, &sup),
            bitmap_is_subset_u256(sub_u, sup_u),
        );
        prop_assert_eq!(
            bitmap_is_subset(&sub, &sup),
            (sub_u & !sup_u) == U256::ZERO,
        );
    }

    #[test]
    fn validate_bitmap_upper_bits_clear_accepts_in_range(
        node_count in 1u32..=256,
        bits in prop::collection::btree_set(any::<usize>(), 0..32),
    ) {
        let mut bm = [0u8; 32];
        for &pos in &bits {
            if (pos as u32) < node_count {
                bitmap_set_bit(&mut bm, pos);
            }
        }
        if bits.iter().all(|&pos| (pos as u32) < node_count) {
            prop_assert!(validate_bitmap_upper_bits_clear(&bm, node_count).is_ok());
        }
    }

    #[test]
    fn effective_selection_size_is_bounded_and_formulaic(
        signatures_required in any::<u8>(),
        redundancy_buffer in any::<u8>(),
        node_count in 1u32..=256,
    ) {
        let got = effective_selection_size(signatures_required, redundancy_buffer, node_count);
        let want = u32::from(signatures_required)
            .saturating_add(u32::from(redundancy_buffer))
            .min(node_count);
        prop_assert_eq!(got, want);
        prop_assert!(got <= node_count);
    }

    #[test]
    fn derive_group_bitmap_is_deterministic(
        seed in any::<[u8; 32]>(),
        node_count in 1u32..=64,
        group_size in 0u32..=64,
    ) {
        prop_assume!(group_size <= node_count);
        let a = derive_group_bitmap(&seed, node_count, group_size).unwrap();
        let b = derive_group_bitmap(&seed, node_count, group_size).unwrap();
        prop_assert_eq!(a, b);
    }

    /// Swept across the full `1..=256` range, not just the first 64-bit limb: the sampler holds
    /// the bitmap as four `u64` limbs, so limb boundaries (64 / 128 / 192 / 256) are where an
    /// off-by-one in the mask or the widening would show up.
    #[test]
    fn derive_group_bitmap_popcount_and_range(
        seed in any::<[u8; 32]>(),
        node_count in 1u32..=256,
        group_size in 0u32..=256,
    ) {
        prop_assume!(group_size <= node_count);
        let bitmap = derive_group_bitmap(&seed, node_count, group_size).unwrap();
        prop_assert_eq!(bitmap_popcount(&bitmap), group_size);
        prop_assert!(bits_in_range(&bitmap, node_count));
    }

    /// Exact limb boundaries, exhaustively rather than by chance.
    #[test]
    fn derive_group_bitmap_at_limb_boundaries(seed in any::<[u8; 32]>()) {
        for node_count in [1u32, 63, 64, 65, 127, 128, 129, 191, 192, 193, 255, 256] {
            for group_size in [0, 1, node_count / 2, node_count - 1, node_count] {
                let bitmap = derive_group_bitmap(&seed, node_count, group_size).unwrap();
                prop_assert_eq!(
                    bitmap_popcount(&bitmap),
                    group_size,
                    "n={} g={}", node_count, group_size,
                );
                prop_assert!(bits_in_range(&bitmap, node_count), "n={} g={}", node_count, group_size);
            }
        }
    }

    #[test]
    fn derive_group_bitmap_complement_equivalence(
        seed in any::<[u8; 32]>(),
        node_count in 2u32..=64,
        group_size in 1u32..=64,
    ) {
        prop_assume!(group_size <= node_count);
        prop_assume!(group_size > node_count / 2);
        prop_assume!(group_size < node_count);

        let direct = derive_group_bitmap(&seed, node_count, group_size).unwrap();
        let excluded =
            derive_group_bitmap(&seed, node_count, node_count - group_size).unwrap();
        let full = full_mask_bytes(node_count);
        let complement = bitmap_store(bitmap_load(&full) ^ bitmap_load(&excluded));
        prop_assert_eq!(direct, complement);
    }

    #[test]
    fn derive_selection_bitmap_is_deterministic(
        source_id in any::<[u8; 32]>(),
        registry_version in any::<u32>(),
        canonical_timestamp in any::<u64>(),
        node_count in 1u32..=64,
        signatures_required in any::<u8>(),
        redundancy_buffer in any::<u8>(),
    ) {
        let a = derive_selection_bitmap(
            &source_id,
            registry_version,
            canonical_timestamp,
            node_count,
            signatures_required,
            redundancy_buffer,
        )
        .unwrap();
        let b = derive_selection_bitmap(
            &source_id,
            registry_version,
            canonical_timestamp,
            node_count,
            signatures_required,
            redundancy_buffer,
        )
        .unwrap();
        prop_assert_eq!(a, b);
    }

    #[test]
    fn mul_mod_matches_bigint_reference(a in any::<[u8; 32]>(), b in any::<[u8; 32]>()) {
        let expected = mul_mod_bigint(&a, &b);
        let got = mul_mod(&a, &b);
        prop_assert_eq!(got, expected);
    }

    /// The 256-bit reduce works in 64-bit limbs; check it against arbitrary-precision `%`.
    #[test]
    fn scalar_reduce_matches_bigint_modulo(x in any::<[u8; 32]>()) {
        let expected = big_to_be32(be32_to_big(&x) % be32_to_big(&SECP256K1_ORDER));
        prop_assert_eq!(secp256k1_scalar_reduce_be(x), expected);
    }

    /// Low-s normalization: `s > n/2` becomes `n - s` (wrapping at 2^256, as the byte-wise
    /// subtraction did) with the recovery-id parity flipped, and a zero result is rejected.
    #[test]
    fn ecdsa_normalize_low_s_matches_bigint_reference(
        signature in any::<[u8; 64]>(),
        recovery_id in 0u8..=1,
    ) {
        let mut s_bytes = [0u8; 32];
        s_bytes.copy_from_slice(&signature[32..64]);

        let n = be32_to_big(&SECP256K1_ORDER);
        let half = &n >> 1u32;
        let s = be32_to_big(&s_bytes);
        let two_256 = BigUint::from(1u8) << 256u32;

        let flips = s > half;
        let want_s = if flips { (&two_256 + &n - &s) % &two_256 } else { s };

        let mut got = signature;
        let result = secp256k1_ecdsa_normalize_low_s(recovery_id, &mut got);

        if want_s == BigUint::from(0u8) {
            prop_assert!(result.is_err(), "zero s must be rejected");
        } else {
            prop_assert_eq!(result.unwrap(), recovery_id ^ u8::from(flips));
            prop_assert_eq!(&got[32..64], &big_to_be32(want_s)[..]);
            prop_assert_eq!(&got[..32], &signature[..32], "r must be untouched");
        }
    }

    #[test]
    fn secp256k1_scalar_validity_matches_order_check(scalar in any::<[u8; 32]>()) {
        let is_zero = scalar == [0u8; 32];
        let below_order = be32_to_big(&scalar) < be32_to_big(&SECP256K1_ORDER);
        prop_assert_eq!(
            secp256k1_scalar_is_valid_nonzero(&scalar),
            !is_zero && below_order,
        );
    }

    #[test]
    fn coalition_accumulator_matches_public_key_combine(keys in arb_fixture_pubkey_subset()) {
        let combined = PublicKey::combine(&keys).unwrap().serialize_compressed();

        let mut acc = CoalitionAccumulator::default();
        for pk in &keys {
            let (x, y) = pubkey_to_xy(pk);
            acc.add_stored_xy(&x, &y).unwrap();
        }
        prop_assert_eq!(acc.compressed_pubkey().unwrap(), combined);

        let xy: Vec<SignerXy> = keys.iter().map(pubkey_to_xy).collect();
        prop_assert_eq!(reconstruct_coalition_key(&xy).unwrap(), combined);
    }

    #[test]
    fn coalition_accumulator_is_commutative(keys in arb_fixture_pubkey_subset()) {
        prop_assume!(keys.len() >= 2);
        let combined = PublicKey::combine(&keys).unwrap().serialize_compressed();

        let mut reversed = keys.clone();
        reversed.reverse();
        let xy_rev: Vec<SignerXy> = reversed.iter().map(pubkey_to_xy).collect();
        prop_assert_eq!(
            reconstruct_coalition_key(&xy_rev).unwrap(),
            combined,
        );
    }

    #[test]
    fn compute_message_hash_is_deterministic(
        payload in arb_attestation_payload(),
        signature in arb_schnorr_signature(),
    ) {
        let a = compute_message_hash(&payload, signature.signers_bitmap);
        let b = compute_message_hash(&payload, signature.signers_bitmap);
        prop_assert_eq!(a, b);
    }
}
