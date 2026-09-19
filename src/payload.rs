//! Attestation payload and signature structs.
//!
//! Field layout matches on-chain instruction args. With `borsh`, structs support wire encode/decode.
//! With `anchor`, the same structs can be used directly in Anchor instruction arguments.

use crate::compute_message_hash;

/// Signed oracle attestation payload.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(
    all(feature = "borsh", not(feature = "anchor")),
    derive(borsh::BorshSerialize, borsh::BorshDeserialize)
)]
#[cfg_attr(
    feature = "anchor",
    derive(anchor_lang::AnchorSerialize, anchor_lang::AnchorDeserialize)
)]
pub struct AttestationPayload {
    pub value: [u8; 32],
    pub source_id: [u8; 32],
    pub registry_version: u32,
    pub signatures_required: u8,
    pub canonical_timestamp: u64,
}

/// Aggregate Schnorr signature material.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(
    all(feature = "borsh", not(feature = "anchor")),
    derive(borsh::BorshSerialize, borsh::BorshDeserialize)
)]
#[cfg_attr(
    feature = "anchor",
    derive(anchor_lang::AnchorSerialize, anchor_lang::AnchorDeserialize)
)]
pub struct SchnorrSignature {
    pub agg_sig_s: [u8; 32],
    pub commitment: [u8; 20],
    pub signers_bitmap: [u8; 32],
}

/// Payload plus aggregate Schnorr signature.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(
    all(feature = "borsh", not(feature = "anchor")),
    derive(borsh::BorshSerialize, borsh::BorshDeserialize)
)]
#[cfg_attr(
    feature = "anchor",
    derive(anchor_lang::AnchorSerialize, anchor_lang::AnchorDeserialize)
)]
pub struct Attestation {
    pub payload: AttestationPayload,
    pub signature: SchnorrSignature,
}

impl Attestation {
    /// Message hash the aggregate signature must verify over.
    pub fn message_hash(&self) -> [u8; 32] {
        compute_message_hash(&self.payload, self.signature.signers_bitmap)
    }
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

    #[cfg(feature = "anchor")]
    #[test]
    fn attestation_types_implement_anchor_serialization() {
        fn assert_anchor_traits<
            T: anchor_lang::AnchorSerialize + anchor_lang::AnchorDeserialize,
        >() {
        }

        assert_anchor_traits::<AttestationPayload>();
        assert_anchor_traits::<SchnorrSignature>();
        assert_anchor_traits::<Attestation>();
    }

    #[cfg(feature = "idl-build")]
    #[test]
    fn anchor_idl_includes_attestation_and_nested_types() {
        use anchor_lang::idl::types::{IdlDefinedFields, IdlType, IdlTypeDefTy};
        use anchor_lang::IdlBuild;
        use std::collections::BTreeMap;

        let definition = Attestation::create_type().expect("Attestation IDL definition");
        assert!(definition.name.ends_with("Attestation"));

        let IdlTypeDefTy::Struct {
            fields: Some(IdlDefinedFields::Named(fields)),
        } = definition.ty
        else {
            panic!("Attestation must be an IDL struct with named fields");
        };

        let defined_field_names = fields
            .iter()
            .filter_map(|field| match &field.ty {
                IdlType::Defined { name, .. } => Some(name.as_str()),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert!(defined_field_names
            .iter()
            .any(|name| name.ends_with("AttestationPayload")));
        assert!(defined_field_names
            .iter()
            .any(|name| name.ends_with("SchnorrSignature")));

        let mut nested = BTreeMap::new();
        Attestation::insert_types(&mut nested);
        assert!(nested
            .values()
            .any(|definition| definition.name.ends_with("AttestationPayload")));
        assert!(nested
            .values()
            .any(|definition| definition.name.ends_with("SchnorrSignature")));
    }
}
