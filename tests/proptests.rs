//! Property-based tests for pure verification primitives.

use ethnum::U256;
use libsecp256k1::{PublicKey, PublicKeyFormat};
use molpha_verifier::{
    bitmap::{
        bitmap_bit_set, bitmap_clear_bit, bitmap_is_subset, bitmap_is_subset_u256, bitmap_load,
        bitmap_popcount_evm, bitmap_set_bit, bitmap_store, derive_group_bitmap,
        effective_selection_size, for_each_set_bit, validate_bitmap_upper_bits_clear,
    },
    coalition::CoalitionAccumulator,
    message::compute_message_hash,
    payload::{DataUpdate, SchnorrSignature},
    scalar::{mul_mod, secp256k1_scalar_is_valid_nonzero},
    selection::derive_selection_bitmap,
    verify::{reconstruct_coalition_key, SignerXy},
};
use num_bigint::BigUint;
use proptest::prelude::*;

const SECP256K1_ORDER: [u8; 32] = [
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
    0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B, 0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41,
];

/// Valid compressed secp256k1 pubkeys (fixture set from `verify` tests).
const FIXTURE_COMPRESSED_KEYS: [[u8; 33]; 8] = [
    [
        0x03, 0xc0, 0x95, 0x27, 0xe9, 0x78, 0xf6, 0xea, 0x69, 0xf0, 0xc6, 0xb7, 0xac, 0x0f, 0xb6,
        0x3a, 0xd0, 0x81, 0xa8, 0xa2, 0x91, 0x15, 0x1c, 0x5a, 0x0b, 0x11, 0x5c, 0xce, 0x43, 0x57,
        0x51, 0xbe, 0x7d,
    ],
    [
        0x02, 0x64, 0xa7, 0x27, 0x04, 0xf3, 0x9f, 0x8d, 0xd1, 0x7f, 0x20, 0xd7, 0x1c, 0x5b, 0x21,
        0xf3, 0x7b, 0x58, 0x52, 0x65, 0x6b, 0xc0, 0x55, 0x54, 0x42, 0xbf, 0x72, 0x72, 0x22, 0xf2,
        0x9d, 0x7e, 0x58,
    ],
    [
        0x02, 0x75, 0xae, 0x1e, 0x3d, 0xac, 0x00, 0xeb, 0x7d, 0xf0, 0x2e, 0x9f, 0xe8, 0xd9, 0x70,
        0x9c, 0x8a, 0x2c, 0x09, 0xa1, 0x1e, 0xd4, 0xf7, 0xd9, 0xaa, 0x46, 0xa7, 0xde, 0xa6, 0xcf,
        0x37, 0x6d, 0x7f,
    ],
    [
        0x02, 0x6c, 0xe2, 0x5b, 0x3a, 0x16, 0x1a, 0xb8, 0xe0, 0xf0, 0x5e, 0x4c, 0xd1, 0xc7, 0x7b,
        0x77, 0x69, 0x6d, 0x26, 0xc6, 0x41, 0xeb, 0xde, 0xa4, 0xe8, 0x1a, 0xa8, 0x9a, 0x90, 0xf3,
        0x2c, 0xfc, 0x54,
    ],
    [
        0x03, 0x5b, 0x95, 0xd7, 0x03, 0x22, 0x8b, 0xef, 0xcc, 0xc3, 0x78, 0x62, 0x9d, 0xc1, 0x98,
        0x04, 0xce, 0xfe, 0x56, 0xc3, 0x3c, 0x64, 0x5f, 0xa4, 0xbc, 0x1a, 0xa0, 0xf3, 0x75, 0xe3,
        0xb4, 0xfa, 0x5e,
    ],
    [
        0x03, 0x99, 0x5e, 0x4b, 0xe0, 0xec, 0xd4, 0x22, 0xbf, 0x25, 0x0a, 0x3d, 0xa3, 0xa0, 0xb8,
        0x34, 0x2e, 0x52, 0x89, 0x3a, 0x3e, 0x06, 0x4f, 0xa6, 0x35, 0x55, 0x73, 0x78, 0xb5, 0x9a,
        0xfa, 0x8b, 0x50,
    ],
    [
        0x03, 0xec, 0x90, 0x6d, 0x0a, 0x1c, 0xfc, 0x3c, 0x7d, 0xec, 0x18, 0x08, 0x8c, 0x3d, 0x14,
        0x4f, 0x32, 0x15, 0x80, 0xec, 0xe0, 0xa6, 0xba, 0xe5, 0xce, 0xb2, 0x8d, 0xcf, 0x8d, 0xc6,
        0xe3, 0xda, 0x03,
    ],
    [
        0x03, 0x27, 0x5f, 0xcf, 0x98, 0x38, 0xb4, 0x7a, 0xac, 0xff, 0x25, 0x1f, 0x4f, 0x09, 0x9f,
        0x80, 0xc6, 0x4a, 0x1a, 0x9a, 0xed, 0xbd, 0xb6, 0x28, 0xc2, 0xc8, 0x7f, 0x2c, 0x5e, 0x12,
        0x3d, 0xd0, 0x40,
    ],
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
    prop::collection::btree_set(0usize..8, 1..=8).prop_map(|indices| {
        indices
            .into_iter()
            .map(|i| {
                PublicKey::parse_slice(
                    &FIXTURE_COMPRESSED_KEYS[i],
                    Some(PublicKeyFormat::Compressed),
                )
                .unwrap()
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

fn arb_data_update() -> impl Strategy<Value = DataUpdate> {
    (
        any::<[u8; 32]>(),
        any::<u32>(),
        prop::collection::vec(any::<u8>(), 0..=256),
        any::<i64>(),
        any::<u8>(),
    )
        .prop_map(
            |(source_id, registry_version, value, canonical_timestamp, signatures_required)| {
                DataUpdate {
                    source_id,
                    registry_version,
                    value,
                    canonical_timestamp,
                    signatures_required,
                }
            },
        )
}

fn arb_schnorr_signature() -> impl Strategy<Value = SchnorrSignature> {
    (any::<[u8; 32]>(), any::<[u8; 20]>(), any::<[u8; 32]>()).prop_map(
        |(agg_sig_s, commitment_addr, signers_bitmap)| SchnorrSignature {
            agg_sig_s,
            commitment_addr,
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
        prop_assert_eq!(bitmap_popcount_evm(&bytes), popcount_manual(&bytes));
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
        let want = (u32::from(signatures_required) + u32::from(redundancy_buffer)).min(node_count);
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

    #[test]
    fn derive_group_bitmap_popcount_and_range(
        seed in any::<[u8; 32]>(),
        node_count in 1u32..=64,
        group_size in 0u32..=64,
    ) {
        prop_assume!(group_size <= node_count);
        let bitmap = derive_group_bitmap(&seed, node_count, group_size).unwrap();
        prop_assert_eq!(bitmap_popcount_evm(&bitmap), group_size);
        prop_assert!(bits_in_range(&bitmap, node_count));
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
        canonical_timestamp in any::<i64>(),
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
        payload in arb_data_update(),
        signature in arb_schnorr_signature(),
        sig_req in any::<u8>(),
    ) {
        let a = compute_message_hash(&payload, signature.signers_bitmap, sig_req);
        let b = compute_message_hash(&payload, signature.signers_bitmap, sig_req);
        prop_assert_eq!(a, b);
    }
}
