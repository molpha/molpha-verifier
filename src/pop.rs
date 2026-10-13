//! Secp256k1 node-key validation, proof-of-possession verification and signing-key rotation.

use libsecp256k1::{PublicKey, PublicKeyFormat};
use solana_keccak_hasher::hashv;
use solana_secp256k1_recover::secp256k1_recover;

use crate::{
    coalition::CoalitionKey,
    scalar::{
        mul_mod, negate_mod_n, secp256k1_ecdsa_normalize_low_s, secp256k1_scalar_is_valid_nonzero,
        secp256k1_scalar_reduce_be,
    },
    verify::verify_aggregate_over_hash_with_coalition_key,
    SignerXy,
};

/// Domain separator for node proofs of possession.
pub const NODE_POP_PREFIX: &[u8] = b"MOLPHA_NODE_POP_V1";

/// Domain separator for node signing-key rotations.
pub const NODE_KEY_ROTATION_PREFIX: &[u8] = b"MOLPHA_NODE_KEY_ROTATION_V1";

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

/// Both signatures that authorize replacing a node's signing key.
///
/// Field layout matches the on-chain instruction args. With `borsh` the struct supports wire
/// encode/decode; with `anchor` it can be used directly as an Anchor instruction argument.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(
    all(feature = "borsh", not(feature = "anchor")),
    derive(borsh::BorshSerialize, borsh::BorshDeserialize)
)]
#[cfg_attr(
    feature = "anchor",
    derive(anchor_lang::AnchorSerialize, anchor_lang::AnchorDeserialize)
)]
pub struct KeyRotationProof {
    /// The replacement key, compressed.
    pub new_public_key_compressed: [u8; 33],
    /// The current key's signature `s` over [`key_rotation_digest`], in the aggregate format.
    pub old_key_sig_s: [u8; 32],
    /// The current key's signature commitment (nonce address) over [`key_rotation_digest`].
    pub old_key_commitment: [u8; 20],
    /// The replacement key's proof of possession `r` (see [`validate_key_and_verify_pop`]).
    pub pop_sig_r: [u8; 32],
    /// The replacement key's proof of possession `s`.
    pub pop_sig_s: [u8; 32],
}

/// Signing-key rotation failure.
#[cfg_attr(feature = "thiserror", derive(thiserror::Error))]
#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub enum KeyRotationError {
    /// The replacement key is not a canonical, recovery-compatible secp256k1 point.
    #[cfg_attr(feature = "thiserror", error("invalid secp256k1 public key"))]
    InvalidPublicKey,
    /// The replacement key's proof of possession is malformed or does not match the key.
    #[cfg_attr(feature = "thiserror", error("invalid proof of possession"))]
    InvalidProof,
    /// The current key's signature over the rotation does not verify.
    #[cfg_attr(
        feature = "thiserror",
        error("the current key did not sign this rotation")
    )]
    InvalidAuthorization,
    /// The replacement key is the current key.
    #[cfg_attr(feature = "thiserror", error("the new key is the current key"))]
    KeyUnchanged,
}

impl From<NodePopError> for KeyRotationError {
    fn from(error: NodePopError) -> Self {
        match error {
            NodePopError::InvalidPublicKey => Self::InvalidPublicKey,
            NodePopError::InvalidProof => Self::InvalidProof,
        }
    }
}

/// Digest both keys sign to rotate `node`'s signing key to `new_public_key_compressed`:
/// `keccak256("MOLPHA_NODE_KEY_ROTATION_V1" ‖ program_id ‖ node ‖ new_public_key_compressed)`.
///
/// `node` is the node account address. It is bound so a rotation cannot be replayed on another
/// node, and the digest names the new key so the signatures authorize that key only. The
/// current key enters through its own signature challenge, and neither the registry version nor
/// a nonce is needed: a rotated-in key is single-use, and a retired key never becomes current
/// again.
pub fn key_rotation_digest(
    program_id: &[u8; 32],
    node: &[u8; 32],
    new_public_key_compressed: &[u8; 33],
) -> [u8; 32] {
    hashv(&[
        NODE_KEY_ROTATION_PREFIX,
        program_id.as_ref(),
        node.as_ref(),
        new_public_key_compressed.as_ref(),
    ])
    .to_bytes()
}

/// Verify a signing-key rotation and return the new key as affine `(x, y)`.
///
/// Requires, over [`key_rotation_digest`]:
/// - a proof of possession by the new key, so a rotation cannot install a rogue key (the
///   coalition key is a plain sum of node keys). The PoP message is the registration one,
///   `keccak256("MOLPHA_NODE_POP_V1" ‖ program_id ‖ digest)`, so a registration PoP cannot be
///   replayed as a rotation PoP or the reverse.
/// - a signature by `old_key`, the node's current key.
///
/// The node authority's own signature (a Solana signer) and single-use of the new key are the
/// caller's to enforce.
pub fn verify_key_rotation(
    program_id: &[u8; 32],
    node: &[u8; 32],
    old_key: &SignerXy,
    proof: &KeyRotationProof,
) -> Result<SignerXy, KeyRotationError> {
    let digest = key_rotation_digest(program_id, node, &proof.new_public_key_compressed);

    let new_key = validate_key_and_verify_pop(
        program_id,
        &digest,
        &proof.new_public_key_compressed,
        &proof.pop_sig_r,
        &proof.pop_sig_s,
    )?;
    if new_key == *old_key {
        return Err(KeyRotationError::KeyUnchanged);
    }

    // A coalition of one: the stored key is its own affine sum, which skips the field inversion.
    let authorized = verify_aggregate_over_hash_with_coalition_key(
        &proof.old_key_sig_s,
        &proof.old_key_commitment,
        &digest,
        core::slice::from_ref(old_key),
        &CoalitionKey {
            x: old_key.0,
            y: old_key.1,
        },
    );
    match authorized {
        Ok(true) => Ok(new_key),
        _ => Err(KeyRotationError::InvalidAuthorization),
    }
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
    // ---- signing-key rotation ----

    use crate::scalar::eth_address_from_uncompressed_pubkey;

    const PROGRAM: [u8; 32] = [1u8; 32];
    const NODE: [u8; 32] = [3u8; 32];

    fn uncompressed_xy(compressed: &[u8; 33]) -> [u8; 64] {
        let key = PublicKey::parse_slice(compressed, Some(PublicKeyFormat::Compressed)).unwrap();
        key.serialize()[1..65].try_into().unwrap()
    }

    /// Single-key Schnorr signature `(s, commitment)` in the aggregate (EVM) format.
    fn sign_aggregate(
        public_key: &[u8; 33],
        secret: &[u8; 32],
        message: &[u8; 32],
        nonce: &[u8; 32],
    ) -> ([u8; 32], [u8; 20]) {
        let commitment =
            eth_address_from_uncompressed_pubkey(uncompressed_xy(&public_key_for_secret(nonce)));
        let x: [u8; 32] = public_key[1..33].try_into().unwrap();
        let parity = [public_key[0] & 1];
        let challenge = secp256k1_scalar_reduce_be(
            hashv(&[
                x.as_ref(),
                parity.as_ref(),
                message.as_ref(),
                commitment.as_ref(),
            ])
            .to_bytes(),
        );
        (add_mod_n(nonce, &mul_mod(&challenge, secret)), commitment)
    }

    fn key_xy(secret: &[u8; 32]) -> SignerXy {
        normalize_public_key(&public_key_for_secret(secret)).unwrap()
    }

    /// A rotation of `node` from `old_secret`'s key to `new_secret`'s key, signed by both.
    fn rotation_proof(
        program_id: &[u8; 32],
        node: &[u8; 32],
        old_secret: &[u8; 32],
        new_secret: &[u8; 32],
    ) -> KeyRotationProof {
        let old_public = public_key_for_secret(old_secret);
        let new_public = public_key_for_secret(new_secret);
        let digest = key_rotation_digest(program_id, node, &new_public);
        let (old_key_sig_s, old_key_commitment) =
            sign_aggregate(&old_public, old_secret, &digest, &scalar(17));
        let (pop_sig_r, pop_sig_s) =
            sign_pop(program_id, &digest, &new_public, new_secret, &scalar(21));
        KeyRotationProof {
            new_public_key_compressed: new_public,
            old_key_sig_s,
            old_key_commitment,
            pop_sig_r,
            pop_sig_s,
        }
    }

    #[test]
    fn rotation_returns_the_new_key() {
        let proof = rotation_proof(&PROGRAM, &NODE, &scalar(9), &scalar(10));
        assert_eq!(
            verify_key_rotation(&PROGRAM, &NODE, &key_xy(&scalar(9)), &proof),
            Ok(key_xy(&scalar(10)))
        );
    }

    #[test]
    fn rotation_digest_is_domain_separated_and_binds_every_input() {
        let new_key = public_key_for_secret(&scalar(10));
        let digest = key_rotation_digest(&PROGRAM, &NODE, &new_key);
        assert_eq!(
            digest,
            hashv(&[
                b"MOLPHA_NODE_KEY_ROTATION_V1".as_ref(),
                PROGRAM.as_ref(),
                NODE.as_ref(),
                new_key.as_ref(),
            ])
            .to_bytes()
        );

        let mut other_program = PROGRAM;
        other_program[0] ^= 1;
        let mut other_node = NODE;
        other_node[0] ^= 1;
        let other_key = public_key_for_secret(&scalar(11));
        for other in [
            key_rotation_digest(&other_program, &NODE, &new_key),
            key_rotation_digest(&PROGRAM, &other_node, &new_key),
            key_rotation_digest(&PROGRAM, &NODE, &other_key),
        ] {
            assert_ne!(other, digest);
        }

        // Neither tag is a prefix of the other, and the registration PoP message over the same
        // bytes differs.
        assert_ne!(derive_node_pop_message(&PROGRAM, &NODE), digest);
        assert!(!NODE_KEY_ROTATION_PREFIX.starts_with(NODE_POP_PREFIX));
        assert!(!NODE_POP_PREFIX.starts_with(NODE_KEY_ROTATION_PREFIX));
    }

    #[test]
    fn rotation_requires_the_current_keys_signature() {
        let old_key = key_xy(&scalar(9));
        let valid = rotation_proof(&PROGRAM, &NODE, &scalar(9), &scalar(10));

        // Signed by some other key.
        let forged = rotation_proof(&PROGRAM, &NODE, &scalar(8), &scalar(10));
        assert_eq!(
            verify_key_rotation(&PROGRAM, &NODE, &old_key, &forged),
            Err(KeyRotationError::InvalidAuthorization)
        );

        let mut bad_s = valid.clone();
        bad_s.old_key_sig_s[31] ^= 1;
        let mut bad_commitment = valid.clone();
        bad_commitment.old_key_commitment[0] ^= 1;
        let mut invalid_scalar = valid.clone();
        invalid_scalar.old_key_sig_s = [0xff; 32];
        let mut zero_scalar = valid;
        zero_scalar.old_key_sig_s = [0u8; 32];
        for proof in [bad_s, bad_commitment, invalid_scalar, zero_scalar] {
            assert_eq!(
                verify_key_rotation(&PROGRAM, &NODE, &old_key, &proof),
                Err(KeyRotationError::InvalidAuthorization)
            );
        }
    }

    #[test]
    fn the_old_keys_signature_is_bound_to_node_program_and_new_key() {
        let old_key = key_xy(&scalar(9));
        let mut other_node = NODE;
        other_node[0] ^= 1;
        let mut other_program = PROGRAM;
        other_program[0] ^= 1;

        // Authorization signed for another node, with a PoP that is right for this one.
        let mut mixed = rotation_proof(&PROGRAM, &NODE, &scalar(9), &scalar(10));
        let for_other_node = rotation_proof(&PROGRAM, &other_node, &scalar(9), &scalar(10));
        mixed.old_key_sig_s = for_other_node.old_key_sig_s;
        mixed.old_key_commitment = for_other_node.old_key_commitment;
        assert_eq!(
            verify_key_rotation(&PROGRAM, &NODE, &old_key, &mixed),
            Err(KeyRotationError::InvalidAuthorization)
        );

        // The same, for another program.
        let mut mixed = rotation_proof(&PROGRAM, &NODE, &scalar(9), &scalar(10));
        let for_other_program = rotation_proof(&other_program, &NODE, &scalar(9), &scalar(10));
        mixed.old_key_sig_s = for_other_program.old_key_sig_s;
        mixed.old_key_commitment = for_other_program.old_key_commitment;
        assert_eq!(
            verify_key_rotation(&PROGRAM, &NODE, &old_key, &mixed),
            Err(KeyRotationError::InvalidAuthorization)
        );

        // Authorization for a different new key.
        let mut mixed = rotation_proof(&PROGRAM, &NODE, &scalar(9), &scalar(10));
        let for_other_key = rotation_proof(&PROGRAM, &NODE, &scalar(9), &scalar(11));
        mixed.old_key_sig_s = for_other_key.old_key_sig_s;
        mixed.old_key_commitment = for_other_key.old_key_commitment;
        assert_eq!(
            verify_key_rotation(&PROGRAM, &NODE, &old_key, &mixed),
            Err(KeyRotationError::InvalidAuthorization)
        );

        // Only the node the old key signed for can use it.
        let proof = rotation_proof(&PROGRAM, &NODE, &scalar(9), &scalar(10));
        assert!(verify_key_rotation(&PROGRAM, &other_node, &old_key, &proof).is_err());
        assert!(verify_key_rotation(&other_program, &NODE, &old_key, &proof).is_err());
    }

    #[test]
    fn rotation_requires_the_new_keys_possession() {
        let old_key = key_xy(&scalar(9));
        let valid = rotation_proof(&PROGRAM, &NODE, &scalar(9), &scalar(10));
        let new_public = valid.new_public_key_compressed;
        let digest = key_rotation_digest(&PROGRAM, &NODE, &new_public);

        // The PoP is made by the old key, not by the key being installed.
        let mut by_old_key = valid.clone();
        (by_old_key.pop_sig_r, by_old_key.pop_sig_s) =
            sign_pop(&PROGRAM, &digest, &new_public, &scalar(9), &scalar(21));
        // A registration-style PoP over the node address instead of the rotation digest.
        let mut registration_style = valid.clone();
        (registration_style.pop_sig_r, registration_style.pop_sig_s) =
            sign_pop(&PROGRAM, &NODE, &new_public, &scalar(10), &scalar(21));
        // A PoP lifted from the same key's rotation of another node.
        let mut other_node = NODE;
        other_node[0] ^= 1;
        let mut replayed = valid.clone();
        let elsewhere = rotation_proof(&PROGRAM, &other_node, &scalar(9), &scalar(10));
        (replayed.pop_sig_r, replayed.pop_sig_s) = (elsewhere.pop_sig_r, elsewhere.pop_sig_s);
        let mut tampered = valid;
        tampered.pop_sig_s[31] ^= 1;

        for proof in [by_old_key, registration_style, replayed, tampered] {
            assert_eq!(
                verify_key_rotation(&PROGRAM, &NODE, &old_key, &proof),
                Err(KeyRotationError::InvalidProof)
            );
        }
    }

    #[test]
    fn a_rogue_key_cannot_be_rotated_in() {
        let honest_secret = scalar(7);
        let target_secret = scalar(23);
        let old_secret = scalar(9);

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

        // The operator can sign for its own current key and knows the target's secret, but not
        // the rogue key's.
        let old_public = public_key_for_secret(&old_secret);
        let digest = key_rotation_digest(&PROGRAM, &NODE, &rogue);
        let (old_key_sig_s, old_key_commitment) =
            sign_aggregate(&old_public, &old_secret, &digest, &scalar(17));
        let (pop_sig_r, pop_sig_s) =
            sign_pop(&PROGRAM, &digest, &rogue, &target_secret, &scalar(29));
        let proof = KeyRotationProof {
            new_public_key_compressed: rogue,
            old_key_sig_s,
            old_key_commitment,
            pop_sig_r,
            pop_sig_s,
        };

        assert_eq!(
            verify_key_rotation(&PROGRAM, &NODE, &key_xy(&old_secret), &proof),
            Err(KeyRotationError::InvalidProof)
        );
    }

    #[test]
    fn a_malformed_new_key_is_rejected() {
        let old_key = key_xy(&scalar(9));
        let valid = rotation_proof(&PROGRAM, &NODE, &scalar(9), &scalar(10));

        let mut zero = valid.clone();
        zero.new_public_key_compressed = [0u8; 33];
        let mut uncompressed_prefix = valid.clone();
        uncompressed_prefix.new_public_key_compressed[0] = 0x04;
        let mut field_overflow = valid;
        field_overflow.new_public_key_compressed = [0xff; 33];
        field_overflow.new_public_key_compressed[0] = 0x02;

        for proof in [zero, uncompressed_prefix, field_overflow] {
            assert_eq!(
                verify_key_rotation(&PROGRAM, &NODE, &old_key, &proof),
                Err(KeyRotationError::InvalidPublicKey)
            );
        }
    }

    #[test]
    fn rotating_to_the_current_key_is_rejected() {
        let proof = rotation_proof(&PROGRAM, &NODE, &scalar(9), &scalar(9));
        assert_eq!(
            verify_key_rotation(&PROGRAM, &NODE, &key_xy(&scalar(9)), &proof),
            Err(KeyRotationError::KeyUnchanged)
        );
    }

    #[test]
    fn rotation_vector_is_pinned() {
        // Deterministic keys and nonces, so other signers (CLI, node client) can reproduce it:
        // program `[1; 32]`, node `[3; 32]`, current secret 9, new secret 10, aggregate nonce 17,
        // PoP nonce 21 (secrets and nonces are big-endian scalars).
        fn unhex<const N: usize>(hex: &str) -> [u8; N] {
            let mut out = [0u8; N];
            for (i, byte) in out.iter_mut().enumerate() {
                *byte = u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).unwrap();
            }
            out
        }

        let proof = KeyRotationProof {
            new_public_key_compressed: unhex(
                "03a0434d9e47f3c86235477c7b1ae6ae5d3442d49b1943c2b752a68e2a47e247c7",
            ),
            old_key_sig_s: unhex(
                "4eb385ddc525b86e70a8aec7e4642b61b4f34312e1353527dcc0a440ad0423cf",
            ),
            old_key_commitment: unhex("252dae0a4b9d9b80f504f6418acd2d364c0c59cd"),
            pop_sig_r: unhex("352bbf4a4cdd12564f93fa332ce333301d9ad40271f8107181340aef25be59d5"),
            pop_sig_s: unhex("6f5983bad23c650ba9cfb4b82920f073790f38c800b1c1dad98b756269f17009"),
        };
        assert_eq!(
            public_key_for_secret(&scalar(9)),
            unhex::<33>("03acd484e2f0c7f65309ad178a9f559abde09796974c57e714c35f110dfc27ccbe")
        );
        assert_eq!(
            key_rotation_digest(&PROGRAM, &NODE, &proof.new_public_key_compressed),
            unhex::<32>("331b9a9c19c4c7f72c68d960fdd661892fa15c49e6f82d9ae3a23265e4be751c")
        );
        assert_eq!(
            proof,
            rotation_proof(&PROGRAM, &NODE, &scalar(9), &scalar(10))
        );
        assert_eq!(
            verify_key_rotation(&PROGRAM, &NODE, &key_xy(&scalar(9)), &proof),
            Ok(key_xy(&scalar(10)))
        );
    }
}
