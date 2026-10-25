//! Integration tests for the exported `solana` feature surface.

#![cfg(all(feature = "solana", feature = "fixtures"))]

use molpha_verifier::fixtures::{
    COMMITMENT, PUBKEYS, REDUNDANCY_BUFFER, REGISTERED_NODE_COUNT, REGISTRY_VERSION, S,
    SIGNATURES_REQUIRED, SIGNERS_BITMAP, SOURCE_ID, TIMESTAMP, VALUE,
};
use molpha_verifier::solana::{
    registry_account_len, verify_attestation, AccountError, RegistryAccount, DISCRIMINATOR_LEN,
    PROGRAM_ID, REGISTRY_DISCRIMINATOR, REGISTRY_MEMBER_LEN, REGISTRY_NODES_OFFSET,
    REGISTRY_SEED_PREFIX,
};
use molpha_verifier::{Attestation, AttestationPayload, SchnorrSignature};

use solana_account_info::AccountInfo;
use solana_program_error::ProgramError;
use solana_pubkey::Pubkey;

/// The program sizes a snapshot to its members, so the table holds exactly `node_count`.
const CAPACITY: usize = REGISTERED_NODE_COUNT as usize;

fn handler(registry: &AccountInfo<'_>, attestation: &Attestation) -> Result<(), ProgramError> {
    verify_attestation(attestation, registry, None)?;
    Ok(())
}

fn node_account(index: usize) -> [u8; 32] {
    let mut account = [0u8; 32];
    account[0] = 0xa0;
    account[31] = index as u8;
    account
}

fn registry_pda(version: u32) -> (Pubkey, u8) {
    Pubkey::derive_program_address(
        &[REGISTRY_SEED_PREFIX, version.to_le_bytes().as_ref()],
        &PROGRAM_ID,
    )
    .expect("registry PDA")
}

/// Registry bytes in the program's zero-copy layout: after the discriminator, `grace_active_until`
/// and `active_from` (i64), `version` (u32), `node_count` (u16), `redundancy_buffer` (u8),
/// `bump` (u8), then the member table.
fn registry_account_data(version: u32) -> Vec<u8> {
    let mut data = vec![0u8; registry_account_len(CAPACITY)];
    data[..DISCRIMINATOR_LEN].copy_from_slice(&REGISTRY_DISCRIMINATOR);
    data[24..28].copy_from_slice(&version.to_le_bytes());
    data[28..30].copy_from_slice(&(REGISTERED_NODE_COUNT as u16).to_le_bytes());
    data[30] = REDUNDANCY_BUFFER;
    data[31] = registry_pda(version).1;
    for (index, (x, y)) in PUBKEYS.iter().enumerate() {
        let offset = REGISTRY_NODES_OFFSET + index * REGISTRY_MEMBER_LEN;
        data[offset..offset + 32].copy_from_slice(&node_account(index));
        data[offset + 32..offset + 64].copy_from_slice(x);
        data[offset + 64..offset + 96].copy_from_slice(y);
    }
    data
}

fn attestation() -> Attestation {
    Attestation {
        payload: AttestationPayload {
            value: VALUE,
            source_id: SOURCE_ID,
            registry_version: REGISTRY_VERSION,
            timestamp: TIMESTAMP,
            signatures_required: SIGNATURES_REQUIRED,
        },
        signature: SchnorrSignature {
            agg_sig_s: S,
            commitment: COMMITMENT,
            signers_bitmap: SIGNERS_BITMAP,
        },
    }
}

/// Owned buffers behind the registry `AccountInfo`.
struct Ledger {
    registry_key: Pubkey,
    registry_data: Vec<u8>,
    registry_lamports: u64,
    owner: Pubkey,
}

impl Ledger {
    fn new() -> Self {
        Self {
            registry_key: registry_pda(REGISTRY_VERSION).0,
            registry_data: registry_account_data(REGISTRY_VERSION),
            registry_lamports: 1,
            owner: PROGRAM_ID,
        }
    }

    fn registry(&mut self) -> AccountInfo<'_> {
        AccountInfo::new(
            &self.registry_key,
            false,
            false,
            &mut self.registry_lamports,
            &mut self.registry_data,
            &self.owner,
            false,
        )
    }
}

#[test]
fn handler_verifies_the_evm_fixture_from_the_registry_alone() {
    let mut ledger = Ledger::new();
    let registry = ledger.registry();
    handler(&registry, &attestation()).expect("fixture must verify");
}

#[test]
fn handler_surfaces_account_errors_as_program_errors() {
    let mut ledger = Ledger::new();
    ledger.owner = Pubkey::new_from_array([9u8; 32]);
    let registry = ledger.registry();

    let error = handler(&registry, &attestation()).unwrap_err();
    assert_eq!(
        error,
        ProgramError::Custom(AccountError::InvalidAccountOwner.code())
    );
}

#[test]
fn registry_view_can_be_held_and_reused_across_calls() {
    let mut ledger = Ledger::new();
    let registry_info = ledger.registry();
    let registry = RegistryAccount::load(&registry_info).expect("load registry");
    let view = registry.view();

    assert_eq!(view.version, REGISTRY_VERSION);
    assert_eq!(view.node_count, REGISTERED_NODE_COUNT as u16);
    assert_eq!(view.redundancy_buffer, REDUNDANCY_BUFFER);
    assert_eq!(view.nodes.len(), CAPACITY);

    let bit = SIGNERS_BITMAP
        .iter()
        .rev()
        .enumerate()
        .find_map(|(byte, v)| (*v != 0).then(|| byte * 8 + v.trailing_zeros() as usize))
        .expect("fixture has signers");
    let member = view.signer(bit).expect("signer is a member");
    assert_eq!(member.account, node_account(bit));
    assert_eq!(member.xy(), PUBKEYS[bit]);
}
