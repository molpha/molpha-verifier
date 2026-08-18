//! Plain attestation payload and signature structs.
//!
//! Field order and types match the on-chain attestation instruction arguments so a mechanical
//! field copy converts between the two. With the `borsh` feature enabled, structs derive
//! `BorshSerialize` / `BorshDeserialize` for wire-format decode/encode.

/// Signed oracle attestation payload.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(
    feature = "borsh",
    derive(borsh::BorshSerialize, borsh::BorshDeserialize)
)]
pub struct AttestationPayload {
    pub value: [u8; 32],
    pub source_id: [u8; 32],
    pub registry_version: u32,
    pub signatures_required: u32,
    pub canonical_timestamp: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(
    feature = "borsh",
    derive(borsh::BorshSerialize, borsh::BorshDeserialize)
)]
pub struct SchnorrSignature {
    pub agg_sig_s: [u8; 32],
    pub commitment_addr: [u8; 20],
    pub signers_bitmap: [u8; 32],
}

/// A signed attestation: payload plus aggregate Schnorr signature.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(
    feature = "borsh",
    derive(borsh::BorshSerialize, borsh::BorshDeserialize)
)]
pub struct Attestation {
    pub payload: AttestationPayload,
    pub signature: SchnorrSignature,
}

#[cfg(all(test, feature = "borsh"))]
mod tests {
    use super::*;
    use borsh::{BorshDeserialize, BorshSerialize};

    /// Fixture `value` bytes (hashed as-is in `compute_message_hash`).
    const FIXTURE_VALUE: [u8; 32] = [
        0xe1, 0xcd, 0x5b, 0x4f, 0x67, 0xac, 0xdc, 0x78, 0x68, 0xc3, 0xb1, 0x5f, 0x7b, 0x6c, 0xc2,
        0xdc, 0x27, 0x70, 0x54, 0x53, 0x71, 0x34, 0x2c, 0xab, 0x76, 0x62, 0x71, 0xbb, 0x3f, 0xd5,
        0xe7, 0x34,
    ];

    /// 80-byte borsh encoding used by `examples/verify_attestation.rs`.
    const FIXTURE_PAYLOAD_BORSH: [u8; 80] = [
        0xe1, 0xcd, 0x5b, 0x4f, 0x67, 0xac, 0xdc, 0x78, 0x68, 0xc3, 0xb1, 0x5f, 0x7b, 0x6c, 0xc2,
        0xdc, 0x27, 0x70, 0x54, 0x53, 0x71, 0x34, 0x2c, 0xab, 0x76, 0x62, 0x71, 0xbb, 0x3f, 0xd5,
        0xe7, 0x34, 0x0b, 0x0c, 0x5c, 0x4a, 0x0e, 0x67, 0x58, 0x69, 0xda, 0xc2, 0x27, 0x2a, 0x40,
        0x04, 0x63, 0x65, 0xa2, 0x9c, 0x8a, 0xe7, 0x63, 0x5e, 0x52, 0xc4, 0x94, 0xd8, 0x40, 0xda,
        0x2e, 0xc8, 0x26, 0xcb, 0x0c, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x7c, 0x06, 0xd6,
        0x65, 0x00, 0x00, 0x00, 0x00,
    ];

    /// 84-byte borsh encoding used by `examples/verify_attestation.rs`.
    const FIXTURE_SIGNATURE_BORSH: [u8; 84] = [
        0x1b, 0x8d, 0xd2, 0x78, 0xb3, 0x67, 0xb3, 0x4d, 0x4e, 0xce, 0x69, 0xb8, 0x8c, 0x28, 0xff,
        0x13, 0x01, 0xb6, 0x72, 0x51, 0xfc, 0x3d, 0x79, 0x26, 0xac, 0xb5, 0x25, 0xd1, 0x1f, 0xd3,
        0x17, 0x1d, 0x51, 0xbe, 0x44, 0x69, 0x33, 0x1a, 0x9e, 0xb3, 0xed, 0x48, 0xb1, 0xd4, 0xe1,
        0x1e, 0xc9, 0xa0, 0xa5, 0x95, 0x2d, 0xf4, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0e, 0x1d,
    ];

    #[test]
    fn fixture_payload_borsh_roundtrip() {
        let decoded =
            AttestationPayload::try_from_slice(&FIXTURE_PAYLOAD_BORSH).expect("decode payload");
        assert_eq!(decoded.value, FIXTURE_VALUE);
        assert_eq!(decoded.registry_version, 12);
        assert_eq!(decoded.signatures_required, 5);
        assert_eq!(decoded.canonical_timestamp, 1_708_525_180);

        let encoded = decoded.try_to_vec().expect("encode payload");
        assert_eq!(encoded.as_slice(), FIXTURE_PAYLOAD_BORSH.as_slice());
    }

    #[test]
    fn fixture_signature_borsh_roundtrip() {
        let decoded =
            SchnorrSignature::try_from_slice(&FIXTURE_SIGNATURE_BORSH).expect("decode signature");
        assert_eq!(decoded.signers_bitmap[30], 0x0e);
        assert_eq!(decoded.signers_bitmap[31], 0x1d);

        let encoded = decoded.try_to_vec().expect("encode signature");
        assert_eq!(encoded.as_slice(), FIXTURE_SIGNATURE_BORSH.as_slice());
    }

    #[test]
    fn fixture_attestation_borsh_roundtrip() {
        let payload =
            AttestationPayload::try_from_slice(&FIXTURE_PAYLOAD_BORSH).expect("decode payload");
        let signature =
            SchnorrSignature::try_from_slice(&FIXTURE_SIGNATURE_BORSH).expect("decode signature");
        let attestation = Attestation { payload, signature };

        let encoded = attestation.try_to_vec().expect("encode attestation");
        let decoded = Attestation::try_from_slice(&encoded).expect("decode attestation");
        assert_eq!(decoded, attestation);
    }
}
