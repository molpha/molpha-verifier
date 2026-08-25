//! External-consumer view of the `solana` feature.
//!
//! The module's own unit tests cover validation behaviour. This file exists to prove the exported
//! surface is actually usable from outside the crate — that the lifetimes on `RegistryAccount`
//! work in an instruction-handler shape, and that `AccountError` flows into `ProgramError` with a
//! plain `?`.

#![cfg(all(feature = "solana", feature = "fixtures"))]

use molpha_verifier::fixtures::{
    CANONICAL_TIMESTAMP, COMMITMENT, PUBKEYS, REDUNDANCY_BUFFER, REGISTERED_NODE_COUNT,
    REGISTRY_VERSION, S, SIGNATURES_REQUIRED, SIGNERS_BITMAP, SOURCE_ID, VALUE,
};
use molpha_verifier::solana::{
    verify_attestation_accounts, AccountError, RegistryAccount, DISCRIMINATOR_LEN,
    NODE_ACCOUNT_LEN, NODE_DISCRIMINATOR, NODE_SEED_PREFIX, REGISTRY_ACCOUNT_LEN,
    REGISTRY_DISCRIMINATOR, REGISTRY_SEED_PREFIX,
};
use molpha_verifier::{Attestation, AttestationPayload, SchnorrSignature};

use solana_program::{account_info::AccountInfo, program_error::ProgramError, pubkey::Pubkey};

const PROGRAM_ID: Pubkey = Pubkey::new_from_array([7u8; 32]);

/// Bits 3, 5, 7, 8, 9, 10, 11 of the fixture's `signersBitmap = 4008`.
const SIGNER_BITS: [usize; 7] = [3, 5, 7, 8, 9, 10, 11];

/// An Anchor-shaped instruction handler: registry account plus `remaining_accounts`, returning
/// `ProgramError` via `?`.
fn handler(
    program_id: &Pubkey,
    registry: &AccountInfo<'_>,
    remaining_accounts: &[AccountInfo<'_>],
    attestation: &Attestation,
) -> Result<(), ProgramError> {
    verify_attestation_accounts(attestation, registry, remaining_accounts, program_id)?;
    Ok(())
}

fn node_owner(index: usize) -> [u8; 32] {
    let mut owner = [0u8; 32];
    owner[0] = 0xa0;
    owner[31] = index as u8;
    owner
}

fn node_pda(index: usize) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[NODE_SEED_PREFIX, node_owner(index).as_ref()], &PROGRAM_ID)
}

fn registry_pda(version: u32) -> (Pubkey, u8) {
    Pubkey::find_program_address(
        &[REGISTRY_SEED_PREFIX, version.to_le_bytes().as_ref()],
        &PROGRAM_ID,
    )
}

const NODE_STATUS_OFFSET: usize = DISCRIMINATOR_LEN + 32 + 32 + 32;
const NODE_BUMP_OFFSET: usize = NODE_STATUS_OFFSET + 1 + 4 + 2 + 7 * 8;

fn fill_node_account(
    data: &mut [u8],
    owner: &[u8; 32],
    x: &[u8; 32],
    y: &[u8; 32],
    status: u8,
    bump: u8,
) {
    data[..DISCRIMINATOR_LEN].copy_from_slice(&NODE_DISCRIMINATOR);
    data[DISCRIMINATOR_LEN..DISCRIMINATOR_LEN + 32].copy_from_slice(owner);
    data[DISCRIMINATOR_LEN + 32..DISCRIMINATOR_LEN + 64].copy_from_slice(x);
    data[DISCRIMINATOR_LEN + 64..DISCRIMINATOR_LEN + 96].copy_from_slice(y);
    data[NODE_STATUS_OFFSET] = status;
    data[NODE_BUMP_OFFSET] = bump;
}

fn node_account_data(index: usize) -> Vec<u8> {
    let (x, y) = PUBKEYS[index];
    let mut data = vec![0u8; NODE_ACCOUNT_LEN];
    fill_node_account(
        &mut data,
        &node_owner(index),
        &x,
        &y,
        0,
        node_pda(index).1,
    );
    data
}

fn registry_account_data(version: u32) -> Vec<u8> {
    let mut data = vec![0u8; REGISTRY_ACCOUNT_LEN];
    data[..DISCRIMINATOR_LEN].copy_from_slice(&REGISTRY_DISCRIMINATOR);
    data[8..12].copy_from_slice(&version.to_le_bytes());
    data[12..14].copy_from_slice(&(REGISTERED_NODE_COUNT as u16).to_le_bytes());
    data[14] = REDUNDANCY_BUFFER;
    data[15] = registry_pda(version).1;
    for index in 0..REGISTERED_NODE_COUNT as usize {
        let offset = 16 + index * 32;
        data[offset..offset + 32].copy_from_slice(&node_pda(index).0.to_bytes());
    }
    data
}

fn attestation() -> Attestation {
    Attestation {
        payload: AttestationPayload {
            value: VALUE,
            source_id: SOURCE_ID,
            registry_version: REGISTRY_VERSION,
            canonical_timestamp: CANONICAL_TIMESTAMP,
            signatures_required: SIGNATURES_REQUIRED,
        },
        signature: SchnorrSignature {
            agg_sig_s: S,
            commitment_addr: COMMITMENT,
            signers_bitmap: SIGNERS_BITMAP,
        },
    }
}

/// Owned buffers behind the `AccountInfo`s. `AccountInfo` borrows lamports and data mutably, so
/// the storage has to outlive them.
struct Ledger {
    registry_key: Pubkey,
    registry_data: Vec<u8>,
    registry_lamports: u64,
    node_keys: Vec<Pubkey>,
    node_data: Vec<Vec<u8>>,
    node_lamports: Vec<u64>,
    owner: Pubkey,
}

impl Ledger {
    fn new() -> Self {
        Self {
            registry_key: registry_pda(REGISTRY_VERSION).0,
            registry_data: registry_account_data(REGISTRY_VERSION),
            registry_lamports: 1,
            node_keys: SIGNER_BITS.iter().map(|i| node_pda(*i).0).collect(),
            node_data: SIGNER_BITS.iter().map(|i| node_account_data(*i)).collect(),
            node_lamports: vec![1; SIGNER_BITS.len()],
            owner: PROGRAM_ID,
        }
    }

    fn accounts(&mut self) -> (AccountInfo<'_>, Vec<AccountInfo<'_>>) {
        let registry = AccountInfo::new(
            &self.registry_key,
            false,
            false,
            &mut self.registry_lamports,
            &mut self.registry_data,
            &self.owner,
            false,
        );
        let nodes = self
            .node_keys
            .iter()
            .zip(self.node_lamports.iter_mut())
            .zip(self.node_data.iter_mut())
            .map(|((key, lamports), data)| {
                AccountInfo::new(key, false, false, lamports, data, &self.owner, false)
            })
            .collect();
        (registry, nodes)
    }
}

#[test]
fn handler_verifies_the_evm_fixture_from_accounts() {
    let mut ledger = Ledger::new();
    let (registry, nodes) = ledger.accounts();
    handler(&PROGRAM_ID, &registry, &nodes, &attestation()).expect("fixture must verify");
}

#[test]
fn handler_surfaces_account_errors_as_program_errors() {
    let mut ledger = Ledger::new();
    ledger.owner = Pubkey::new_from_array([9u8; 32]);
    let (registry, nodes) = ledger.accounts();

    let error = handler(&PROGRAM_ID, &registry, &nodes, &attestation()).unwrap_err();
    assert_eq!(
        error,
        ProgramError::Custom(AccountError::InvalidAccountOwner.code())
    );
}

#[test]
fn registry_account_can_be_held_and_reused_across_calls() {
    // The borrow guard must survive being bound to a local and read from repeatedly — this is the
    // shape a program uses when it verifies several attestations against one snapshot.
    let mut ledger = Ledger::new();
    let (registry_info, _nodes) = ledger.accounts();
    let registry = RegistryAccount::load(&registry_info, &PROGRAM_ID).expect("load registry");

    let view = registry.view();
    assert_eq!(view.version, REGISTRY_VERSION);
    assert_eq!(view.node_count, REGISTERED_NODE_COUNT as u16);
    assert_eq!(
        view.nodes[SIGNER_BITS[0]],
        node_pda(SIGNER_BITS[0]).0.to_bytes()
    );

    // Still readable after the first view is dropped.
    assert_eq!(registry.view().redundancy_buffer, REDUNDANCY_BUFFER);
    assert_eq!(*registry.key(), registry_pda(REGISTRY_VERSION).0);
}
