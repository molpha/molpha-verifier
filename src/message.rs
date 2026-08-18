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
///     MESSAGE_PREFIX, value, sourceId, registryVersion, signaturesRequired,
///     canonicalTimestamp, signersBitmap
/// ))
/// ```
pub fn compute_message_hash(payload: &AttestationPayload, signers_bitmap: [u8; 32]) -> [u8; 32] {
    let registry_version_bytes = payload.registry_version.to_be_bytes();
    let signatures_required_bytes = payload.signatures_required.to_be_bytes();
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
    use crate::fixtures::{
        CANONICAL_TIMESTAMP, MESSAGE_HASH, REGISTRY_VERSION, SIGNATURES_REQUIRED, SIGNERS_BITMAP,
        SOURCE_ID, VALUE,
    };

    fn fixture_payload() -> AttestationPayload {
        AttestationPayload {
            value: VALUE,
            source_id: SOURCE_ID,
            registry_version: REGISTRY_VERSION,
            signatures_required: SIGNATURES_REQUIRED,
            canonical_timestamp: CANONICAL_TIMESTAMP,
        }
    }

    fn fixture_signers_bitmap() -> [u8; 32] {
        SIGNERS_BITMAP
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
            compute_message_hash(&p, fixture_signers_bitmap()),
            compute_message_hash(&p, fixture_signers_bitmap())
        );
    }

    #[test]
    fn compute_message_hash_matches_evm_fixture() {
        let p = fixture_payload();
        assert_eq!(
            compute_message_hash(&p, fixture_signers_bitmap()),
            MESSAGE_HASH,
        );
    }

    #[test]
    fn compute_message_hash_is_sensitive_to_each_field() {
        let base = fixture_payload();
        let base_hash = compute_message_hash(&base, fixture_signers_bitmap());

        let mut a = fixture_payload();
        a.registry_version += 1;
        assert_ne!(
            compute_message_hash(&a, fixture_signers_bitmap()),
            base_hash
        );

        let mut b = fixture_payload();
        b.signatures_required += 1;
        assert_ne!(
            compute_message_hash(&b, fixture_signers_bitmap()),
            base_hash
        );

        let c = fixture_payload();
        let mut signers_bitmap = fixture_signers_bitmap();
        signers_bitmap[31] ^= 0x01;
        assert_ne!(compute_message_hash(&c, signers_bitmap), base_hash);

        let mut d = fixture_payload();
        d.value[0] ^= 0xff;
        assert_ne!(
            compute_message_hash(&d, fixture_signers_bitmap()),
            base_hash
        );

        let mut e = fixture_payload();
        e.canonical_timestamp += 1;
        assert_ne!(
            compute_message_hash(&e, fixture_signers_bitmap()),
            base_hash
        );

        let mut f = fixture_payload();
        f.source_id[0] ^= 0xff;
        assert_ne!(
            compute_message_hash(&f, fixture_signers_bitmap()),
            base_hash
        );
    }
}
