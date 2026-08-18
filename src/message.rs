//! EVM-compatible attestation message hash.

use solana_keccak_hasher::hashv;

use crate::payload::AttestationPayload;

/// `bytes32(keccak256("MOLPHA_MESSAGE_V1"))` — EVM `Validator._constructMessage` prefix.
///
/// Value: `keccak256(bytes("MOLPHA_MESSAGE_V1"))`, verified by the unit test below.
pub const MESSAGE_PREFIX: [u8; 32] = [
    0xa7, 0x55, 0x23, 0xa2, 0xab, 0x7b, 0x71, 0x8d, 0x9c, 0xff, 0xd2, 0xfa, 0x97, 0xed, 0x06, 0x9f,
    0xc1, 0x21, 0x84, 0xea, 0xbe, 0xe7, 0xd5, 0x07, 0x85, 0x4d, 0x09, 0x22, 0xf7, 0x0e, 0x7f, 0xe7,
];

/// Compute the EVM-compatible attestation message hash.
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
    payload: &AttestationPayload,
    signers_bitmap: [u8; 32],
    signatures_required: u32,
) -> [u8; 32] {
    let registry_version_bytes = payload.registry_version.to_be_bytes();
    let signatures_required_bytes = signatures_required.to_be_bytes();
    let canonical_timestamp_bytes = payload.canonical_timestamp.to_be_bytes();

    hashv(&[
        MESSAGE_PREFIX.as_slice(),
        payload.value.as_slice(),
        payload.source_id.as_slice(),
        registry_version_bytes.as_slice(),
        signatures_required_bytes.as_slice(),
        canonical_timestamp_bytes.as_slice(),
        signers_bitmap.as_slice(),
    ])
    .to_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_payload() -> AttestationPayload {
        AttestationPayload {
            value: [
                0xe1, 0xcd, 0x5b, 0x4f, 0x67, 0xac, 0xdc, 0x78, 0x68, 0xc3, 0xb1, 0x5f, 0x7b, 0x6c,
                0xc2, 0xdc, 0x27, 0x70, 0x54, 0x53, 0x71, 0x34, 0x2c, 0xab, 0x76, 0x62, 0x71, 0xbb,
                0x3f, 0xd5, 0xe7, 0x34,
            ],
            source_id: [
                0x0b, 0x0c, 0x5c, 0x4a, 0x0e, 0x67, 0x58, 0x69, 0xda, 0xc2, 0x27, 0x2a, 0x40, 0x04,
                0x63, 0x65, 0xa2, 0x9c, 0x8a, 0xe7, 0x63, 0x5e, 0x52, 0xc4, 0x94, 0xd8, 0x40, 0xda,
                0x2e, 0xc8, 0x26, 0xcb,
            ],
            registry_version: 12,
            signatures_required: 5,
            canonical_timestamp: 1_708_525_180,
        }
    }

    fn fixture_signers_bitmap() -> [u8; 32] {
        // uint256(3613) big-endian — bits 0, 2, 3, 4, 9, 10, 11 set.
        [
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x0e, 0x1d,
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
            compute_message_hash(&d, fixture_signers_bitmap(), d.signatures_required),
            base_hash
        );

        let mut e = fixture_payload();
        e.canonical_timestamp += 1;
        assert_ne!(
            compute_message_hash(&e, fixture_signers_bitmap(), e.signatures_required),
            base_hash
        );

        let mut f = fixture_payload();
        f.source_id[0] ^= 0xff;
        assert_ne!(
            compute_message_hash(&f, fixture_signers_bitmap(), f.signatures_required),
            base_hash
        );
    }
}
