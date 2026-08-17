//! EVM-compatible `DataUpdate` message hash.

use solana_keccak_hasher::hashv;

use crate::payload::DataUpdate;

/// `bytes32(keccak256("MOLPHA_MESSAGE_V1"))` — EVM `Validator._constructMessage` prefix.
///
/// Value: `keccak256(bytes("MOLPHA_MESSAGE_V1"))`, verified by the unit test below.
pub const MESSAGE_PREFIX: [u8; 32] = [
    0xa7, 0x55, 0x23, 0xa2, 0xab, 0x7b, 0x71, 0x8d, 0x9c, 0xff, 0xd2, 0xfa, 0x97, 0xed, 0x06, 0x9f,
    0xc1, 0x21, 0x84, 0xea, 0xbe, 0xe7, 0xd5, 0x07, 0x85, 0x4d, 0x09, 0x22, 0xf7, 0x0e, 0x7f, 0xe7,
];

/// Compute the EVM-compatible `DataUpdate` message hash.
///
/// Matches `Validator._constructMessage` in the EVM reference implementation:
/// ```text
/// keccak256(abi.encodePacked(
///     MESSAGE_PREFIX, sourceId, registryVersion, signaturesRequired,
///     signersBitmap, value, canonicalTimestamp
/// ))
/// ```
///
/// `signatures_required` is passed explicitly (not read from `payload`) because callers may
/// verify against a value distinct from `payload.signatures_required` (e.g. `job.signatures_required`).
pub fn compute_message_hash(
    payload: &DataUpdate,
    signers_bitmap: [u8; 32],
    signatures_required: u8,
) -> [u8; 32] {
    let registry_version_bytes = payload.registry_version.to_be_bytes();
    let signatures_required_bytes = u32::from(signatures_required).to_be_bytes();
    let canonical_timestamp_bytes = (payload.canonical_timestamp as u64).to_be_bytes();

    hashv(&[
        MESSAGE_PREFIX.as_slice(),
        payload.source_id.as_slice(),
        registry_version_bytes.as_slice(),
        signatures_required_bytes.as_slice(),
        signers_bitmap.as_slice(),
        payload.value.as_slice(),
        canonical_timestamp_bytes.as_slice(),
    ])
    .to_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_payload() -> DataUpdate {
        DataUpdate {
            // "solana-compat-job" right-padded to 32 bytes.
            source_id: [
                0x73, 0x6f, 0x6c, 0x61, 0x6e, 0x61, 0x2d, 0x63, 0x6f, 0x6d, 0x70, 0x61, 0x74, 0x2d,
                0x6a, 0x6f, 0x62, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00,
            ],
            registry_version: 1,
            // "solana-compat-val" right-padded to 32 bytes.
            value: vec![
                0x73, 0x6f, 0x6c, 0x61, 0x6e, 0x61, 0x2d, 0x63, 0x6f, 0x6d, 0x70, 0x61, 0x74, 0x2d,
                0x76, 0x61, 0x6c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00,
            ],
            canonical_timestamp: 1_700_000_123,
            signatures_required: 8,
        }
    }

    fn fixture_signers_bitmap() -> [u8; 32] {
        // uint256(255) big-endian — bits 0..7 set.
        [
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0xff,
        ]
    }

    #[test]
    fn message_prefix_is_keccak_of_domain() {
        let expected = hashv(&[b"MOLPHA_MESSAGE_V1"]).to_bytes();
        assert_eq!(MESSAGE_PREFIX, expected);
    }

    #[test]
    fn compute_message_hash_is_deterministic() {
        let p = fixture_payload();
        assert_eq!(
            compute_message_hash(&p, fixture_signers_bitmap(), p.signatures_required),
            compute_message_hash(&p, fixture_signers_bitmap(), p.signatures_required)
        );
    }

    #[test]
    fn compute_message_hash_is_sensitive_to_each_field() {
        let base = fixture_payload();
        let base_hash =
            compute_message_hash(&base, fixture_signers_bitmap(), base.signatures_required);

        let mut a = fixture_payload();
        a.registry_version += 1;
        assert_ne!(
            compute_message_hash(&a, fixture_signers_bitmap(), a.signatures_required),
            base_hash
        );

        let b = fixture_payload();
        assert_ne!(
            compute_message_hash(
                &b,
                fixture_signers_bitmap(),
                b.signatures_required.saturating_sub(1)
            ),
            base_hash
        );

        let c = fixture_payload();
        let mut signers_bitmap = fixture_signers_bitmap();
        signers_bitmap[31] ^= 0x01;
        assert_ne!(
            compute_message_hash(&c, signers_bitmap, c.signatures_required),
            base_hash
        );

        let mut d = fixture_payload();
        d.value[0] ^= 0xff;
        assert_ne!(
            compute_message_hash(&d, signers_bitmap, d.signatures_required),
            base_hash
        );

        let mut e = fixture_payload();
        e.canonical_timestamp += 1;
        assert_ne!(
            compute_message_hash(&e, signers_bitmap, e.signatures_required),
            base_hash
        );

        let mut f = fixture_payload();
        f.source_id[0] ^= 0xff;
        assert_ne!(
            compute_message_hash(&f, signers_bitmap, f.signatures_required),
            base_hash
        );
    }
}
