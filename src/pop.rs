//! Secp256k1 node-key validation and proof-of-possession verification.

use libsecp256k1::{PublicKey, PublicKeyFormat};
use solana_keccak_hasher::hashv;
use solana_secp256k1_recover::secp256k1_recover;

use crate::{
    scalar::{
        mul_mod, negate_mod_n, secp256k1_ecdsa_normalize_low_s, secp256k1_scalar_is_valid_nonzero,
        secp256k1_scalar_reduce_be,
    },
    SignerXy,
};

/// Domain separator for node proofs of possession.
pub const NODE_POP_PREFIX: &[u8] = b"MOLPHA_NODE_POP_V1";

/// Node key / PoP validation failure.
#[cfg_attr(feature = "thiserror", derive(thiserror::Error))]
#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub enum NodePopError {
    /// Compressed key is not a canonical, recovery-compatible secp256k1 point.
    #[cfg_attr(feature = "thiserror", error("invalid secp256k1 public key"))]
    InvalidPublicKey,
    /// PoP is malformed or does not match the key.
    #[cfg_attr(feature = "thiserror", error("invalid proof of possession"))]
    InvalidProof,
}

/// Validate a compressed node key, verify its PoP, and return affine `(x, y)` for [`SignerXy`].
pub fn validate_key_and_verify_pop(
    program_id: &[u8; 32],
    node_id: &[u8; 32],
    public_key_compressed: &[u8; 33],
    pop_sig_r: &[u8; 32],
    pop_sig_s: &[u8; 32],
) -> Result<SignerXy, NodePopError> {
    let coordinates = normalize_public_key(public_key_compressed)?;
    verify_pop(
        program_id,
        node_id,
        public_key_compressed,
        &coordinates.0,
        pop_sig_r,
        pop_sig_s,
    )?;
    Ok(coordinates)
}

fn normalize_public_key(public_key_compressed: &[u8; 33]) -> Result<SignerXy, NodePopError> {
    let public_key =
        PublicKey::parse_slice(public_key_compressed, Some(PublicKeyFormat::Compressed))
            .map_err(|_| NodePopError::InvalidPublicKey)?;

    let mut x = [0u8; 32];
    x.copy_from_slice(&public_key_compressed[1..33]);
    if !secp256k1_scalar_is_valid_nonzero(&x)
        || public_key.serialize_compressed() != *public_key_compressed
    {
        return Err(NodePopError::InvalidPublicKey);
    }

    let uncompressed = public_key.serialize();
    let mut y = [0u8; 32];
    y.copy_from_slice(&uncompressed[33..65]);
    Ok((x, y))
}

fn verify_pop(
    program_id: &[u8; 32],
    node_id: &[u8; 32],
    public_key_compressed: &[u8; 33],
    public_key_x: &[u8; 32],
    pop_sig_r: &[u8; 32],
    pop_sig_s: &[u8; 32],
) -> Result<(), NodePopError> {
    if !secp256k1_scalar_is_valid_nonzero(pop_sig_s) {
        return Err(NodePopError::InvalidProof);
    }

    let mut nonce_compressed = [0u8; 33];
    nonce_compressed[0] = 0x02;
    nonce_compressed[1..33].copy_from_slice(pop_sig_r);
    let expected_nonce =
        PublicKey::parse_slice(&nonce_compressed, Some(PublicKeyFormat::Compressed))
            .map_err(|_| NodePopError::InvalidProof)?
            .serialize();

    let parity_bit = [public_key_compressed[0] & 1];
    let pop_message = derive_node_pop_message(program_id, node_id);
    let challenge = secp256k1_scalar_reduce_be(
        hashv(&[
            public_key_x.as_ref(),
            parity_bit.as_ref(),
            pop_message.as_ref(),
            pop_sig_r.as_ref(),
        ])
        .to_bytes(),
    );

    // ECDSA recovery with r=P.x yields R = sG - eP; low-S flips recovery parity.
    let ecdsa_hash = negate_mod_n(&mul_mod(pop_sig_s, public_key_x));
    let ecdsa_s = negate_mod_n(&mul_mod(&challenge, public_key_x));
    if ecdsa_s == [0u8; 32] {
        return Err(NodePopError::InvalidProof);
    }

    let mut ecdsa_signature = [0u8; 64];
    ecdsa_signature[..32].copy_from_slice(public_key_x);
    ecdsa_signature[32..64].copy_from_slice(&ecdsa_s);
    let recovery_id = secp256k1_ecdsa_normalize_low_s(parity_bit[0], &mut ecdsa_signature)
        .map_err(|_| NodePopError::InvalidProof)?;
    let recovered_nonce = secp256k1_recover(&ecdsa_hash, recovery_id, &ecdsa_signature)
        .map_err(|_| NodePopError::InvalidProof)?
        .to_bytes();

    if recovered_nonce.as_ref() != &expected_nonce[1..65] {
        return Err(NodePopError::InvalidProof);
    }
    Ok(())
}

fn derive_node_pop_message(program_id: &[u8; 32], node_id: &[u8; 32]) -> [u8; 32] {
    hashv(&[NODE_POP_PREFIX, program_id.as_ref(), node_id.as_ref()]).to_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    use libsecp256k1::{curve::ECMultGenContext, SecretKey};
    use num_bigint::BigUint;

    const SECP256K1_ORDER: [u8; 32] = [
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFE, 0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B, 0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36,
        0x41, 0x41,
    ];

    fn scalar(value: u8) -> [u8; 32] {
        let mut out = [0u8; 32];
        out[31] = value;
        out
    }

    fn public_key_for_secret(secret: &[u8; 32]) -> [u8; 33] {
        let secret = SecretKey::parse(secret).expect("valid secret");
        let context = ECMultGenContext::new_boxed();
        PublicKey::from_secret_key_with_context(&secret, &context).serialize_compressed()
    }

    fn add_mod_n(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
        let order = BigUint::from_bytes_be(&SECP256K1_ORDER);
        let sum = (BigUint::from_bytes_be(a) + BigUint::from_bytes_be(b)) % order;
        let bytes = sum.to_bytes_be();
        let mut out = [0u8; 32];
        out[32 - bytes.len()..].copy_from_slice(&bytes);
        out
    }

    fn sign_pop(
        program_id: &[u8; 32],
        node_id: &[u8; 32],
        public_key_compressed: &[u8; 33],
        signing_secret: &[u8; 32],
        nonce: &[u8; 32],
    ) -> ([u8; 32], [u8; 32]) {
        let mut canonical_nonce = *nonce;
        let mut nonce_public_key = public_key_for_secret(&canonical_nonce);
        if nonce_public_key[0] == 0x03 {
            canonical_nonce = negate_mod_n(&canonical_nonce);
            nonce_public_key = public_key_for_secret(&canonical_nonce);
        }
        let r: [u8; 32] = nonce_public_key[1..33].try_into().unwrap();
        let public_key_x: [u8; 32] = public_key_compressed[1..33].try_into().unwrap();
        let parity = [public_key_compressed[0] & 1];
        let message = derive_node_pop_message(program_id, node_id);
        let challenge = secp256k1_scalar_reduce_be(
            hashv(&[
                public_key_x.as_ref(),
                parity.as_ref(),
                message.as_ref(),
                r.as_ref(),
            ])
            .to_bytes(),
        );
        let s = add_mod_n(&canonical_nonce, &mul_mod(&challenge, signing_secret));
        (r, s)
    }

    #[test]
    fn valid_key_and_pop_return_normalized_coordinates() {
        let program_id = [1u8; 32];
        let node_id = [2u8; 32];
        let secret = scalar(9);
        let compressed = public_key_for_secret(&secret);
        let (r, s) = sign_pop(&program_id, &node_id, &compressed, &secret, &scalar(13));

        let (x, y) =
            validate_key_and_verify_pop(&program_id, &node_id, &compressed, &r, &s).unwrap();
        assert_eq!(x, compressed[1..33]);

        let mut full = [0u8; 65];
        full[0] = 0x04;
        full[1..33].copy_from_slice(&x);
        full[33..65].copy_from_slice(&y);
        let parsed = PublicKey::parse_slice(&full, Some(PublicKeyFormat::Full)).unwrap();
        assert_eq!(parsed.serialize_compressed(), compressed);
    }

    #[test]
    fn malformed_keys_are_rejected_before_the_proof() {
        let program_id = [1u8; 32];
        let node_id = [2u8; 32];
        let r = scalar(1);
        let s = scalar(1);
        assert_eq!(
            validate_key_and_verify_pop(&program_id, &node_id, &[0u8; 33], &r, &s),
            Err(NodePopError::InvalidPublicKey)
        );

        let mut invalid_prefix = public_key_for_secret(&scalar(3));
        invalid_prefix[0] = 0x04;
        assert_eq!(
            validate_key_and_verify_pop(&program_id, &node_id, &invalid_prefix, &r, &s),
            Err(NodePopError::InvalidPublicKey)
        );

        let mut field_overflow = [0xff; 33];
        field_overflow[0] = 0x02;
        assert_eq!(
            validate_key_and_verify_pop(&program_id, &node_id, &field_overflow, &r, &s),
            Err(NodePopError::InvalidPublicKey)
        );
    }

    #[test]
    fn pop_is_domain_and_key_sensitive() {
        let program_id = [1u8; 32];
        let node_id = [2u8; 32];
        let secret = scalar(9);
        let compressed = public_key_for_secret(&secret);
        let (r, s) = sign_pop(&program_id, &node_id, &compressed, &secret, &scalar(13));

        let mut other_program = program_id;
        other_program[0] ^= 1;
        assert_eq!(
            validate_key_and_verify_pop(&other_program, &node_id, &compressed, &r, &s),
            Err(NodePopError::InvalidProof)
        );

        let mut other_node_id = node_id;
        other_node_id[0] ^= 1;
        assert_eq!(
            validate_key_and_verify_pop(&program_id, &other_node_id, &compressed, &r, &s),
            Err(NodePopError::InvalidProof)
        );

        let other_key = public_key_for_secret(&scalar(10));
        assert_eq!(
            validate_key_and_verify_pop(&program_id, &node_id, &other_key, &r, &s),
            Err(NodePopError::InvalidProof)
        );
    }

    #[test]
    fn malformed_pop_values_are_rejected() {
        let program_id = [1u8; 32];
        let node_id = [2u8; 32];
        let secret = scalar(5);
        let compressed = public_key_for_secret(&secret);
        let (r, _) = sign_pop(&program_id, &node_id, &compressed, &secret, &scalar(19));

        assert_eq!(
            validate_key_and_verify_pop(&program_id, &node_id, &compressed, &[0u8; 32], &scalar(1),),
            Err(NodePopError::InvalidProof)
        );
        assert_eq!(
            validate_key_and_verify_pop(&program_id, &node_id, &compressed, &r, &[0u8; 32]),
            Err(NodePopError::InvalidProof)
        );
        assert_eq!(
            validate_key_and_verify_pop(&program_id, &node_id, &compressed, &r, &SECP256K1_ORDER),
            Err(NodePopError::InvalidProof)
        );
    }

    #[test]
    fn rogue_key_cannot_use_attackers_known_scalar_as_pop() {
        let program_id = [1u8; 32];
        let node_id = [2u8; 32];
        let honest_secret = scalar(7);
        let target_secret = scalar(23);

        let target = PublicKey::parse_slice(
            &public_key_for_secret(&target_secret),
            Some(PublicKeyFormat::Compressed),
        )
        .unwrap();
        let neg_honest = PublicKey::parse_slice(
            &public_key_for_secret(&negate_mod_n(&honest_secret)),
            Some(PublicKeyFormat::Compressed),
        )
        .unwrap();
        let rogue = PublicKey::combine(&[target, neg_honest])
            .unwrap()
            .serialize_compressed();
        let (r, s) = sign_pop(&program_id, &node_id, &rogue, &target_secret, &scalar(29));

        assert_eq!(
            validate_key_and_verify_pop(&program_id, &node_id, &rogue, &r, &s),
            Err(NodePopError::InvalidProof)
        );
    }
}
