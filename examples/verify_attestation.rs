//! Verify a Molpha [`Attestation`] using the 12-node registry fixture.
//!
//! Run:
//! ```text
//! cargo run -p molpha-verifier --example verify_attestation --features borsh,fixtures
//! ```

use borsh::BorshDeserialize;
use molpha_verifier::{
    compute_message_hash, fixtures, verify, Attestation, AttestationError, AttestationPayload,
    SchnorrSignature,
};

fn main() -> Result<(), AttestationError> {
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
    println!("timestamp:               {}", attestation.payload.timestamp);

    let message_hash =
        compute_message_hash(&attestation.payload, attestation.signature.signers_bitmap);
    println!("message_hash:             0x{}", hex_encode(&message_hash));

    // The registry snapshot's member table: account address and (x, y) key per bit.
    let nodes: Vec<molpha_verifier::NodeEntry> = fixtures::PUBKEYS
        .iter()
        .enumerate()
        .map(|(i, (x, y))| molpha_verifier::NodeEntry {
            account: [i as u8; 32],
            x: *x,
            y: *y,
        })
        .collect();

    let registry = molpha_verifier::RegistryView {
        version: fixtures::REGISTRY_VERSION,
        node_count: fixtures::REGISTERED_NODE_COUNT as u16,
        redundancy_buffer: fixtures::REDUNDANCY_BUFFER,
        nodes: &nodes,
    };
    verify(&attestation, &registry, None)?;

    println!("aggregate Schnorr signature: OK");
    Ok(())
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
