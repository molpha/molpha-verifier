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
    pub signatures_required: u8,
    pub canonical_timestamp: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(
    feature = "borsh",
    derive(borsh::BorshSerialize, borsh::BorshDeserialize)
)]
pub struct SchnorrSignature {
    pub agg_sig_s: [u8; 32],
    pub commitment: [u8; 20],
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
    use crate::fixtures::{PAYLOAD_BORSH, SIGNATURE_BORSH, VALUE};
    use borsh::BorshDeserialize;

    #[test]
    fn fixture_payload_borsh_roundtrip() {
        let decoded = AttestationPayload::try_from_slice(&PAYLOAD_BORSH).expect("decode payload");
        assert_eq!(decoded.value, VALUE);
        assert_eq!(decoded.registry_version, 12);
        assert_eq!(decoded.signatures_required, 5);
        assert_eq!(decoded.canonical_timestamp, 1_705_257_421);

        let encoded = borsh::to_vec(&decoded).expect("encode payload");
        assert_eq!(encoded.as_slice(), PAYLOAD_BORSH.as_slice());
    }

    #[test]
    fn fixture_signature_borsh_roundtrip() {
        let decoded = SchnorrSignature::try_from_slice(&SIGNATURE_BORSH).expect("decode signature");
        assert_eq!(decoded.signers_bitmap[30], 0x0f);
        assert_eq!(decoded.signers_bitmap[31], 0xa8);

        let encoded = borsh::to_vec(&decoded).expect("encode signature");
        assert_eq!(encoded.as_slice(), SIGNATURE_BORSH.as_slice());
    }

    #[test]
    fn fixture_attestation_borsh_roundtrip() {
        let payload = AttestationPayload::try_from_slice(&PAYLOAD_BORSH).expect("decode payload");
        let signature =
            SchnorrSignature::try_from_slice(&SIGNATURE_BORSH).expect("decode signature");
        let attestation = Attestation { payload, signature };

        let encoded = borsh::to_vec(&attestation).expect("encode attestation");
        let decoded = Attestation::try_from_slice(&encoded).expect("decode attestation");
        assert_eq!(decoded, attestation);
    }
}
