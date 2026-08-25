//! Verify a Molpha [`Attestation`] using the 12-node registry fixture.
//!
//! Run:
//! ```text
//! cargo run -p molpha-verifier --example verify_attestation --features borsh,fixtures
//! ```

use borsh::BorshDeserialize;
use molpha_verifier::{
    bitmap::for_each_set_bit, compute_message_hash, fixtures, verify_attestation, Attestation,
    AttestationError, AttestationPayload, SchnorrSignature,
};

fn main() -> Result<(), AttestationError> {
    // 1. Decode the wire-format attestation (e.g. from instruction args).
    let payload = AttestationPayload::try_from_slice(&fixtures::PAYLOAD_BORSH)
        .expect("fixture payload borsh must decode");
    let signature = SchnorrSignature::try_from_slice(&fixtures::SIGNATURE_BORSH)
        .expect("fixture signature borsh must decode");
    let attestation = Attestation {
        payload: payload.clone(),
        signature: signature.clone(),
    };
    let mut attestation_borsh = fixtures::PAYLOAD_BORSH.to_vec();
    attestation_borsh.extend_from_slice(&fixtures::SIGNATURE_BORSH);
    let decoded_attestation = Attestation::try_from_slice(&attestation_borsh)
        .expect("fixture attestation borsh must decode");
    assert_eq!(decoded_attestation, attestation);

    println!(
        "decoded source_id:        0x{}",
        hex_encode(&attestation.payload.source_id)
    );
    println!(
        "decoded value:            0x{}",
        hex_encode(&attestation.payload.value)
    );
    println!(
        "registry_version:         {}",
        attestation.payload.registry_version
    );
    println!(
        "signatures_required:      {}",
        attestation.payload.signatures_required
    );
    println!(
        "canonical_timestamp:      {}",
        attestation.payload.canonical_timestamp
    );

    let message_hash =
        compute_message_hash(&attestation.payload, attestation.signature.signers_bitmap);
    println!("message_hash:             0x{}", hex_encode(&message_hash));

    // 2. Verify aggregate Schnorr signature.
    //
    // `node_count` is the registry size for `payload.registry_version`. Seven signers at bitmap
    // positions 3, 5, 7, 8, 9, 10, 11 (signersBitmap = 4008); threshold 5; redundancy_buffer 2.
    // `ordered_signers` are the signing nodes' (x, y) pubkeys in ascending bitmap-bit order.
    let mut ordered_signers = Vec::new();
    for_each_set_bit(&fixtures::SIGNERS_BITMAP, |i| {
        ordered_signers.push(fixtures::PUBKEYS[i]);
    });

    verify_attestation(
        &attestation,
        fixtures::REGISTERED_NODE_COUNT,
        fixtures::REDUNDANCY_BUFFER,
        &ordered_signers,
    )?;

    println!("aggregate Schnorr signature: OK");
    Ok(())
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
