//! Solana account adapters — verify from `&[AccountInfo]`.
//!
//! Opt-in (`solana` feature): validates Molpha `Registry` / `Node` accounts and calls
//! [`verify_attestation_resolved`]. Reads Anchor layouts (8-byte discriminator + body) without
//! depending on `anchor-lang`.
//!
//! # Checks
//!
//! Before trusting account data:
//! 1. **Owner** — `account.owner == program_id`
//! 2. **Discriminator** — matches [`REGISTRY_DISCRIMINATOR`] / [`NODE_DISCRIMINATOR`]
//! 3. **Length** — at least [`REGISTRY_ACCOUNT_LEN`] / [`NODE_ACCOUNT_LEN`]
//! 4. **Well-formedness** — `Node` status tag is in range
//!
//! Node status is range-checked only; historical snapshots may still use deactivated nodes.
//! Body fields are read at fixed offsets pinned to the program layout. Discriminator / length
//! checks fail closed on rename / truncation; appending fields stays compatible.
//!
//! # Usage
//! ```ignore
//! use molpha_verifier::solana::verify_attestation_accounts;
//!
//! // `node_accounts`: signer Node accounts in ascending signers_bitmap bit order.
//! verify_attestation_accounts(
//!     &attestation,
//!     &registry_account,
//!     ctx.remaining_accounts,
//!     ctx.program_id,
//! )?;
//! ```

use core::cell::Ref;

use solana_account_info::AccountInfo;
use solana_program_error::ProgramError;
use solana_pubkey::Pubkey;

use crate::{
    onchain::{verify_aggregate_over_hash_resolved, verify_attestation_resolved},
    state::MAX_REGISTRY_NODES,
    Attestation, AttestationError, NodeEntry, RegistryView, SchnorrSignature,
};

/// Registry PDA seeds: `[REGISTRY_SEED_PREFIX, version.to_le_bytes(), [bump]]`.
pub const REGISTRY_SEED_PREFIX: &[u8] = b"molpha_registry";

/// Node PDA seeds: `[NODE_SEED_PREFIX, owner, [bump]]`.
pub const NODE_SEED_PREFIX: &[u8] = b"molpha_node";

/// Anchor discriminator for `Registry` (`sha256("account:Registry")[..8]`).
pub const REGISTRY_DISCRIMINATOR: [u8; 8] = [47, 174, 110, 246, 184, 182, 252, 218];

/// Anchor discriminator for `Node` (`sha256("account:Node")[..8]`).
pub const NODE_DISCRIMINATOR: [u8; 8] = [208, 53, 1, 3, 49, 122, 180, 49];

/// Anchor account discriminator length.
pub const DISCRIMINATOR_LEN: usize = 8;

/// Serialized `Registry` account length including discriminator.
pub const REGISTRY_ACCOUNT_LEN: usize = 8_208;

/// Serialized `Node` account length including discriminator.
pub const NODE_ACCOUNT_LEN: usize = 168;

// Registry is zero_copy / repr(C): version(u32), node_count(u16), redundancy_buffer(u8), bump(u8),
// then nodes[[u8;32]; 256]. Header is 8 bytes with no padding.
const REGISTRY_VERSION_OFFSET: usize = DISCRIMINATOR_LEN;
const REGISTRY_NODE_COUNT_OFFSET: usize = REGISTRY_VERSION_OFFSET + 4;
const REGISTRY_REDUNDANCY_BUFFER_OFFSET: usize = REGISTRY_NODE_COUNT_OFFSET + 2;
const REGISTRY_BUMP_OFFSET: usize = REGISTRY_REDUNDANCY_BUFFER_OFFSET + 1;
const REGISTRY_NODES_OFFSET: usize = REGISTRY_BUMP_OFFSET + 1;
const REGISTRY_NODES_LEN: usize = MAX_REGISTRY_NODES * 32;

const _: () = assert!(REGISTRY_NODES_OFFSET + REGISTRY_NODES_LEN == REGISTRY_ACCOUNT_LEN);

// Node is Borsh: owner, pubkey_x, pubkey_y, status, then trailing fields through bump.
const NODE_OWNER_OFFSET: usize = DISCRIMINATOR_LEN;
const NODE_PUBKEY_X_OFFSET: usize = NODE_OWNER_OFFSET + 32;
const NODE_PUBKEY_Y_OFFSET: usize = NODE_PUBKEY_X_OFFSET + 32;
const NODE_STATUS_OFFSET: usize = NODE_PUBKEY_Y_OFFSET + 32;
// ip(4) + port(2) + seven u64 fields + bump(1)
const NODE_BUMP_OFFSET: usize = NODE_STATUS_OFFSET + 1 + 4 + 2 + 7 * 8;

const _: () = assert!(NODE_BUMP_OFFSET + 1 == NODE_ACCOUNT_LEN);

/// Highest `NodeStatus` tag (`Tombstoned = 3`).
const NODE_STATUS_MAX_TAG: u8 = 3;

/// Base for [`AccountError::code`] (`0x4D4F_0000` = ASCII `"MO"`).
pub const ERROR_CODE_BASE: u32 = 0x4D4F_0000;

/// Account I/O or verification failure.
///
/// Wraps [`AttestationError`] so one `?` covers both paths.
#[cfg_attr(feature = "thiserror", derive(thiserror::Error))]
#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub enum AccountError {
    /// Verification failed.
    #[cfg_attr(feature = "thiserror", error("{0}"))]
    Attestation(AttestationError),
    /// Account data already mutably borrowed.
    #[cfg_attr(feature = "thiserror", error("account data is already borrowed"))]
    AccountBorrowFailed,
    /// Account not owned by the program.
    #[cfg_attr(feature = "thiserror", error("account is not owned by the program"))]
    InvalidAccountOwner,
    /// Registry discriminator or length mismatch.
    #[cfg_attr(
        feature = "thiserror",
        error("registry account discriminator or length mismatch")
    )]
    InvalidRegistryAccount,
    /// Registry is not the canonical PDA for its version.
    #[cfg_attr(
        feature = "thiserror",
        error("registry account is not the canonical PDA for its version")
    )]
    InvalidRegistryPda,
    /// Node discriminator, length, or body mismatch.
    #[cfg_attr(
        feature = "thiserror",
        error("node account discriminator, length, or body mismatch")
    )]
    InvalidNodeAccount,
    /// Node is not the canonical PDA for its owner.
    #[cfg_attr(
        feature = "thiserror",
        error("node account is not the canonical PDA for its owner")
    )]
    InvalidNodePda,
}

impl AccountError {
    /// Stable numeric code (`ERROR_CODE_BASE` + offset). Wrapped attestation errors share code 0.
    pub fn code(&self) -> u32 {
        let offset = match self {
            Self::Attestation(_) => 0,
            Self::AccountBorrowFailed => 1,
            Self::InvalidAccountOwner => 2,
            Self::InvalidRegistryAccount => 3,
            Self::InvalidRegistryPda => 4,
            Self::InvalidNodeAccount => 5,
            Self::InvalidNodePda => 6,
        };
        ERROR_CODE_BASE + offset
    }
}

impl From<AttestationError> for AccountError {
    fn from(error: AttestationError) -> Self {
        Self::Attestation(error)
    }
}

impl From<AccountError> for ProgramError {
    fn from(error: AccountError) -> Self {
        ProgramError::Custom(error.code())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Signer {
    pub x: [u8; 32],
    pub y: [u8; 32],
}

impl Signer {
    fn from_node_account_bytes(data: &[u8]) -> Result<Self, AccountError> {
        if data.len() < NODE_ACCOUNT_LEN || data[..DISCRIMINATOR_LEN] != NODE_DISCRIMINATOR {
            return Err(AccountError::InvalidNodeAccount);
        }
        if data[NODE_STATUS_OFFSET] > NODE_STATUS_MAX_TAG {
            return Err(AccountError::InvalidNodeAccount);
        }
        Ok(Self {
            x: read_32(data, NODE_PUBKEY_X_OFFSET),
            y: read_32(data, NODE_PUBKEY_Y_OFFSET),
        })
    }
}

#[inline]
fn read_32(data: &[u8], offset: usize) -> [u8; 32] {
    data[offset..offset + 32]
        .try_into()
        .expect("length checked by caller")
}

/// Validated, borrowed `Registry` account (holds the data borrow for zero-copy `nodes`).
pub struct RegistryAccount<'a> {
    key: Pubkey,
    data: Ref<'a, [u8]>,
}

impl<'a> RegistryAccount<'a> {
    /// Borrow and validate a `Registry` account (owner / discriminator / length).
    pub fn load(account: &'a AccountInfo<'_>, program_id: &Pubkey) -> Result<Self, AccountError> {
        if account.owner != program_id {
            return Err(AccountError::InvalidAccountOwner);
        }
        let data = account
            .try_borrow_data()
            .map_err(|_| AccountError::AccountBorrowFailed)?;
        let data = Ref::map(data, |bytes| &**bytes);

        if data.len() < REGISTRY_ACCOUNT_LEN || data[..DISCRIMINATOR_LEN] != REGISTRY_DISCRIMINATOR
        {
            return Err(AccountError::InvalidRegistryAccount);
        }

        let registry = Self {
            key: *account.key,
            data,
        };
        Ok(registry)
    }

    pub fn key(&self) -> &Pubkey {
        &self.key
    }

    pub fn version(&self) -> u32 {
        u32::from_le_bytes(
            self.data[REGISTRY_VERSION_OFFSET..REGISTRY_VERSION_OFFSET + 4]
                .try_into()
                .expect("length checked in load"),
        )
    }

    pub fn node_count(&self) -> u16 {
        u16::from_le_bytes(
            self.data[REGISTRY_NODE_COUNT_OFFSET..REGISTRY_NODE_COUNT_OFFSET + 2]
                .try_into()
                .expect("length checked in load"),
        )
    }

    pub fn redundancy_buffer(&self) -> u8 {
        self.data[REGISTRY_REDUNDANCY_BUFFER_OFFSET]
    }

    pub fn bump(&self) -> u8 {
        self.data[REGISTRY_BUMP_OFFSET]
    }

    /// Full ordered node-address array; only `[..node_count()]` is populated.
    pub fn nodes(&self) -> &[[u8; 32]] {
        let bytes = &self.data[REGISTRY_NODES_OFFSET..REGISTRY_NODES_OFFSET + REGISTRY_NODES_LEN];
        // SAFETY: `bytes` is exactly `MAX_REGISTRY_NODES * 32` (bounds checked in `load`).
        // `[u8; 32]` has alignment 1; returned slice borrows `self` with the data guard.
        unsafe {
            core::slice::from_raw_parts(bytes.as_ptr().cast::<[u8; 32]>(), MAX_REGISTRY_NODES)
        }
    }

    /// Framework-agnostic view for resolution / verification.
    pub fn view(&self) -> RegistryView<'_> {
        RegistryView {
            version: self.version(),
            node_count: self.node_count(),
            redundancy_buffer: self.redundancy_buffer(),
            nodes: self.nodes(),
        }
    }
}

impl core::fmt::Debug for RegistryAccount<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RegistryAccount")
            .field("key", &self.key)
            .field("version", &self.version())
            .field("node_count", &self.node_count())
            .field("redundancy_buffer", &self.redundancy_buffer())
            .field("bump", &self.bump())
            .finish_non_exhaustive()
    }
}

/// Validate and parse one `Node` account into a [`NodeEntry`].
pub fn resolve_node(
    account: &AccountInfo<'_>,
    program_id: &Pubkey,
) -> Result<NodeEntry, AccountError> {
    if account.owner != program_id {
        return Err(AccountError::InvalidAccountOwner);
    }
    let data = account
        .try_borrow_data()
        .map_err(|_| AccountError::AccountBorrowFailed)?;
    let node = Signer::from_node_account_bytes(&data)?;
    Ok(NodeEntry {
        account: account.key.to_bytes(),
        x: node.x,
        y: node.y,
    })
}

/// Validate and parse signer `Node` accounts into [`NodeEntry`]s.
pub fn resolve_nodes(
    accounts: &[AccountInfo<'_>],
    program_id: &Pubkey,
) -> Result<Vec<NodeEntry>, AccountError> {
    accounts
        .iter()
        .map(|account| resolve_node(account, program_id))
        .collect()
}

/// Verify an attestation from its `Registry` and signer `Node` accounts.
pub fn verify_attestation_accounts(
    attestation: &Attestation,
    registry_account: &AccountInfo<'_>,
    node_accounts: &[AccountInfo<'_>],
    program_id: &Pubkey,
) -> Result<(), AccountError> {
    let registry = RegistryAccount::load(registry_account, program_id)?;
    let entries = resolve_nodes(node_accounts, program_id)?;
    verify_attestation_resolved(attestation, &registry.view(), &entries)?;
    Ok(())
}

/// Verify an aggregate over an arbitrary message hash from accounts (dispute / slash).
///
/// `Ok(true)` = valid, `Ok(false)` = invalid (slashable), `Err` = malformed accounts or input.
#[allow(clippy::too_many_arguments)]
pub fn verify_aggregate_over_hash_accounts(
    registry_account: &AccountInfo<'_>,
    signature: SchnorrSignature,
    message_hash: &[u8; 32],
    registry_version: u32,
    node_accounts: &[AccountInfo<'_>],
    program_id: &Pubkey,
) -> Result<bool, AccountError> {
    let registry = RegistryAccount::load(registry_account, program_id)?;
    if registry.version() != registry_version {
        return Err(AccountError::InvalidRegistryAccount);
    }
    let entries = resolve_nodes(node_accounts, program_id)?;
    Ok(verify_aggregate_over_hash_resolved(
        &registry.view(),
        &signature,
        message_hash,
        &entries,
    )?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bitmap::for_each_set_bit;
    use crate::fixtures::{
        CANONICAL_TIMESTAMP, COMMITMENT, PUBKEYS, REDUNDANCY_BUFFER, REGISTERED_NODE_COUNT,
        REGISTRY_VERSION, S, SIGNATURES_REQUIRED, SIGNERS_BITMAP, SOURCE_ID, VALUE,
    };
    use crate::message::compute_message_hash;
    use crate::payload::{AttestationPayload, SchnorrSignature};

    const PROGRAM_ID: Pubkey = Pubkey::new_from_array([7u8; 32]);

    fn node_owner(index: usize) -> [u8; 32] {
        let mut owner = [0u8; 32];
        owner[0] = 0xa0;
        owner[31] = index as u8;
        owner
    }

    fn node_pda(index: usize) -> (Pubkey, u8) {
        Pubkey::derive_program_address(&[NODE_SEED_PREFIX, node_owner(index).as_ref()], &PROGRAM_ID)
            .expect("node PDA")
    }

    fn registry_pda(version: u32) -> (Pubkey, u8) {
        Pubkey::derive_program_address(
            &[REGISTRY_SEED_PREFIX, version.to_le_bytes().as_ref()],
            &PROGRAM_ID,
        )
        .expect("registry PDA")
    }

    fn fill_node_account(
        data: &mut [u8],
        owner: &[u8; 32],
        x: &[u8; 32],
        y: &[u8; 32],
        status: u8,
        bump: u8,
    ) {
        assert_eq!(data.len(), NODE_ACCOUNT_LEN);
        data[..DISCRIMINATOR_LEN].copy_from_slice(&NODE_DISCRIMINATOR);
        data[NODE_OWNER_OFFSET..NODE_OWNER_OFFSET + 32].copy_from_slice(owner);
        data[NODE_PUBKEY_X_OFFSET..NODE_PUBKEY_X_OFFSET + 32].copy_from_slice(x);
        data[NODE_PUBKEY_Y_OFFSET..NODE_PUBKEY_Y_OFFSET + 32].copy_from_slice(y);
        data[NODE_STATUS_OFFSET] = status;
        data[NODE_BUMP_OFFSET] = bump;
    }

    fn node_account_data(index: usize) -> Vec<u8> {
        let (_, bump) = node_pda(index);
        let (x, y) = PUBKEYS[index];
        let mut data = vec![0u8; NODE_ACCOUNT_LEN];
        fill_node_account(&mut data, &node_owner(index), &x, &y, 0, bump);
        data
    }

    fn registry_account_data(version: u32) -> Vec<u8> {
        let (_, bump) = registry_pda(version);
        let mut data = vec![0u8; REGISTRY_ACCOUNT_LEN];
        data[..DISCRIMINATOR_LEN].copy_from_slice(&REGISTRY_DISCRIMINATOR);
        data[REGISTRY_VERSION_OFFSET..REGISTRY_VERSION_OFFSET + 4]
            .copy_from_slice(&version.to_le_bytes());
        data[REGISTRY_NODE_COUNT_OFFSET..REGISTRY_NODE_COUNT_OFFSET + 2]
            .copy_from_slice(&(REGISTERED_NODE_COUNT as u16).to_le_bytes());
        data[REGISTRY_REDUNDANCY_BUFFER_OFFSET] = REDUNDANCY_BUFFER;
        data[REGISTRY_BUMP_OFFSET] = bump;
        for index in 0..REGISTERED_NODE_COUNT as usize {
            let offset = REGISTRY_NODES_OFFSET + index * 32;
            data[offset..offset + 32].copy_from_slice(&node_pda(index).0.to_bytes());
        }
        data
    }

    fn fixture_attestation() -> Attestation {
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
                commitment: COMMITMENT,
                signers_bitmap: SIGNERS_BITMAP,
            },
        }
    }

    fn signer_indices() -> Vec<usize> {
        let mut indices = Vec::new();
        for_each_set_bit(&SIGNERS_BITMAP, |bit| indices.push(bit));
        indices
    }

    /// Owned buffers behind `AccountInfo`s.
    struct Accounts {
        registry_key: Pubkey,
        registry_data: Vec<u8>,
        registry_lamports: u64,
        node_keys: Vec<Pubkey>,
        node_data: Vec<Vec<u8>>,
        node_lamports: Vec<u64>,
        owner: Pubkey,
    }

    impl Accounts {
        fn new() -> Self {
            Self::with_version(REGISTRY_VERSION)
        }

        fn with_version(version: u32) -> Self {
            let indices = signer_indices();
            Self {
                registry_key: registry_pda(version).0,
                registry_data: registry_account_data(version),
                registry_lamports: 1,
                node_keys: indices.iter().map(|i| node_pda(*i).0).collect(),
                node_data: indices.iter().map(|i| node_account_data(*i)).collect(),
                node_lamports: vec![1; indices.len()],
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

        fn nodes(&mut self) -> Vec<AccountInfo<'_>> {
            self.node_keys
                .iter()
                .zip(self.node_lamports.iter_mut())
                .zip(self.node_data.iter_mut())
                .map(|((key, lamports), data)| {
                    AccountInfo::new(key, false, false, lamports, data, &self.owner, false)
                })
                .collect()
        }

        fn split(&mut self) -> (AccountInfo<'_>, Vec<AccountInfo<'_>>) {
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
    fn discriminators_match_anchor_derivation() {
        // Anchor: sha256("account:<Name>")[..8]
        use sha2::{Digest, Sha256};
        let registry: [u8; 8] = Sha256::digest(b"account:Registry")[..8].try_into().unwrap();
        let node: [u8; 8] = Sha256::digest(b"account:Node")[..8].try_into().unwrap();
        assert_eq!(registry, REGISTRY_DISCRIMINATOR);
        assert_eq!(node, NODE_DISCRIMINATOR);
    }

    #[test]
    fn node_body_matches_declared_account_length() {
        let data = node_account_data(0);
        assert_eq!(data.len(), NODE_ACCOUNT_LEN);
        assert_eq!(NODE_ACCOUNT_LEN, DISCRIMINATOR_LEN + 160);
    }

    #[test]
    fn nodes_slice_matches_raw_account_bytes() {
        let mut accounts = Accounts::new();
        let info = accounts.registry();
        let registry = RegistryAccount::load(&info, &PROGRAM_ID).expect("load registry");

        let nodes = registry.nodes();
        assert_eq!(nodes.len(), MAX_REGISTRY_NODES);
        for (index, node) in nodes.iter().enumerate() {
            let offset = REGISTRY_NODES_OFFSET + index * 32;
            assert_eq!(&node[..], &registry.data[offset..offset + 32]);
        }
        for (index, node) in nodes
            .iter()
            .enumerate()
            .take(REGISTERED_NODE_COUNT as usize)
        {
            assert_eq!(*node, node_pda(index).0.to_bytes());
        }
        assert_eq!(nodes[REGISTERED_NODE_COUNT as usize], [0u8; 32]);
    }

    #[test]
    fn registry_account_exposes_header_fields() {
        let mut accounts = Accounts::new();
        let info = accounts.registry();
        let registry = RegistryAccount::load(&info, &PROGRAM_ID).expect("load registry");

        assert_eq!(registry.version(), REGISTRY_VERSION);
        assert_eq!(registry.node_count(), REGISTERED_NODE_COUNT as u16);
        assert_eq!(registry.redundancy_buffer(), REDUNDANCY_BUFFER);
        assert_eq!(registry.bump(), registry_pda(REGISTRY_VERSION).1);
        assert_eq!(*registry.key(), registry_pda(REGISTRY_VERSION).0);

        let view = registry.view();
        assert_eq!(view.version, REGISTRY_VERSION);
        assert_eq!(view.node_count, REGISTERED_NODE_COUNT as u16);
        assert_eq!(view.redundancy_buffer, REDUNDANCY_BUFFER);
        assert_eq!(view.nodes.len(), MAX_REGISTRY_NODES);
    }

    #[test]
    fn registry_load_rejects_foreign_owner() {
        let mut accounts = Accounts::new();
        accounts.owner = Pubkey::new_from_array([9u8; 32]);
        let info = accounts.registry();
        assert_eq!(
            RegistryAccount::load(&info, &PROGRAM_ID).unwrap_err(),
            AccountError::InvalidAccountOwner
        );
    }

    #[test]
    fn registry_load_rejects_wrong_discriminator() {
        let mut accounts = Accounts::new();
        accounts.registry_data[0] ^= 0xff;
        let info = accounts.registry();
        assert_eq!(
            RegistryAccount::load(&info, &PROGRAM_ID).unwrap_err(),
            AccountError::InvalidRegistryAccount
        );
    }

    #[test]
    fn registry_load_rejects_short_account() {
        let mut accounts = Accounts::new();
        accounts.registry_data.truncate(REGISTRY_ACCOUNT_LEN - 1);
        let info = accounts.registry();
        assert_eq!(
            RegistryAccount::load(&info, &PROGRAM_ID).unwrap_err(),
            AccountError::InvalidRegistryAccount
        );
    }

    #[test]
    fn registry_load_accepts_non_canonical_pda() {
        // Owner/discriminator/length checked; key is not re-derived from body.
        let mut accounts = Accounts::new();
        accounts.registry_key = Pubkey::new_from_array([0x33u8; 32]);
        let info = accounts.registry();
        let registry = RegistryAccount::load(&info, &PROGRAM_ID).expect("load registry");
        assert_eq!(*registry.key(), Pubkey::new_from_array([0x33u8; 32]));
        assert_eq!(registry.version(), REGISTRY_VERSION);
    }

    #[test]
    fn registry_load_accepts_tampered_bump() {
        let mut accounts = Accounts::new();
        let tampered_bump = accounts.registry_data[REGISTRY_BUMP_OFFSET].wrapping_sub(1);
        accounts.registry_data[REGISTRY_BUMP_OFFSET] = tampered_bump;
        let info = accounts.registry();
        let registry = RegistryAccount::load(&info, &PROGRAM_ID).expect("load registry");
        assert_eq!(registry.bump(), tampered_bump);
    }

    #[test]
    fn registry_load_reads_version_from_body_without_pda_check() {
        let mut accounts = Accounts::new();
        accounts.registry_data[REGISTRY_VERSION_OFFSET..REGISTRY_VERSION_OFFSET + 4]
            .copy_from_slice(&(REGISTRY_VERSION + 1).to_le_bytes());
        let info = accounts.registry();
        let registry = RegistryAccount::load(&info, &PROGRAM_ID).expect("load registry");
        assert_eq!(registry.version(), REGISTRY_VERSION + 1);
    }

    #[test]
    fn registry_load_accepts_appended_trailing_bytes() {
        let mut accounts = Accounts::new();
        accounts.registry_data.extend_from_slice(&[0u8; 16]);
        let info = accounts.registry();
        let registry = RegistryAccount::load(&info, &PROGRAM_ID).expect("load registry");
        assert_eq!(registry.version(), REGISTRY_VERSION);
    }

    #[test]
    fn registry_load_rejects_already_borrowed_data() {
        let mut accounts = Accounts::new();
        let info = accounts.registry();
        let _guard = info.data.borrow_mut();
        assert_eq!(
            RegistryAccount::load(&info, &PROGRAM_ID).unwrap_err(),
            AccountError::AccountBorrowFailed
        );
    }

    #[test]
    fn resolve_nodes_returns_entries_in_account_order() {
        let mut accounts = Accounts::new();
        let infos = accounts.nodes();
        let entries = resolve_nodes(&infos, &PROGRAM_ID).expect("resolve nodes");

        let indices = signer_indices();
        assert_eq!(entries.len(), indices.len());
        for (entry, index) in entries.iter().zip(indices) {
            let (x, y) = PUBKEYS[index];
            assert_eq!(entry.account, node_pda(index).0.to_bytes());
            assert_eq!(entry.x, x);
            assert_eq!(entry.y, y);
        }
    }

    #[test]
    fn resolve_nodes_rejects_foreign_owner() {
        let mut accounts = Accounts::new();
        accounts.owner = Pubkey::new_from_array([9u8; 32]);
        let infos = accounts.nodes();
        assert_eq!(
            resolve_nodes(&infos, &PROGRAM_ID).unwrap_err(),
            AccountError::InvalidAccountOwner
        );
    }

    #[test]
    fn resolve_nodes_rejects_wrong_discriminator() {
        let mut accounts = Accounts::new();
        accounts.node_data[1][0] ^= 0xff;
        let infos = accounts.nodes();
        assert_eq!(
            resolve_nodes(&infos, &PROGRAM_ID).unwrap_err(),
            AccountError::InvalidNodeAccount
        );
    }

    #[test]
    fn resolve_nodes_rejects_registry_account_passed_as_node() {
        let mut accounts = Accounts::new();
        accounts.node_data[0] = registry_account_data(REGISTRY_VERSION);
        let infos = accounts.nodes();
        assert_eq!(
            resolve_nodes(&infos, &PROGRAM_ID).unwrap_err(),
            AccountError::InvalidNodeAccount
        );
    }

    #[test]
    fn resolve_nodes_rejects_short_account() {
        let mut accounts = Accounts::new();
        accounts.node_data[0].truncate(NODE_ACCOUNT_LEN - 1);
        let infos = accounts.nodes();
        assert_eq!(
            resolve_nodes(&infos, &PROGRAM_ID).unwrap_err(),
            AccountError::InvalidNodeAccount
        );
    }

    #[test]
    fn resolve_nodes_rejects_invalid_status_tag() {
        let mut accounts = Accounts::new();
        accounts.node_data[0][DISCRIMINATOR_LEN + 96] = 9;
        let infos = accounts.nodes();
        assert_eq!(
            resolve_nodes(&infos, &PROGRAM_ID).unwrap_err(),
            AccountError::InvalidNodeAccount
        );
    }

    #[test]
    fn resolve_nodes_accepts_non_canonical_pda() {
        let mut accounts = Accounts::new();
        accounts.node_keys[2] = Pubkey::new_from_array([0x44u8; 32]);
        let infos = accounts.nodes();
        let entries = resolve_nodes(&infos, &PROGRAM_ID).expect("resolve nodes");
        assert_eq!(
            entries[2].account,
            Pubkey::new_from_array([0x44u8; 32]).to_bytes()
        );
    }

    #[test]
    fn resolve_nodes_accepts_swapped_owner_field() {
        // Owner field is not consulted during resolution.
        let mut accounts = Accounts::new();
        let other_owner = node_owner(1);
        accounts.node_data[0][DISCRIMINATOR_LEN..DISCRIMINATOR_LEN + 32]
            .copy_from_slice(&other_owner);
        let infos = accounts.nodes();
        assert!(resolve_nodes(&infos, &PROGRAM_ID).is_ok());
    }

    #[test]
    fn resolve_nodes_accepts_appended_trailing_bytes() {
        let mut accounts = Accounts::new();
        accounts.node_data[0].extend_from_slice(&[0u8; 8]);
        let infos = accounts.nodes();
        assert!(resolve_nodes(&infos, &PROGRAM_ID).is_ok());
    }

    #[test]
    fn resolve_nodes_accepts_non_active_status() {
        let mut accounts = Accounts::new();
        accounts.node_data[0][DISCRIMINATOR_LEN + 96] = 3; // Tombstoned
        let infos = accounts.nodes();
        assert!(resolve_nodes(&infos, &PROGRAM_ID).is_ok());
    }

    #[test]
    fn node_status_max_tag_is_enforced() {
        let mut data = node_account_data(0);
        data[NODE_STATUS_OFFSET] = NODE_STATUS_MAX_TAG;
        assert!(Signer::from_node_account_bytes(&data).is_ok());

        data[NODE_STATUS_OFFSET] = NODE_STATUS_MAX_TAG + 1;
        assert!(Signer::from_node_account_bytes(&data).is_err());
    }

    #[test]
    fn node_account_framing_checks() {
        let full = node_account_data(3);

        for len in [0usize, 1, DISCRIMINATOR_LEN, NODE_ACCOUNT_LEN - 1] {
            let short = &full[..len];
            assert!(
                Signer::from_node_account_bytes(short).is_err(),
                "truncation to {len} must be rejected",
            );
        }

        let mut wrong_discriminator = full.clone();
        wrong_discriminator[0] ^= 0xff;
        assert!(Signer::from_node_account_bytes(&wrong_discriminator).is_err());

        let mut extended = full;
        extended.extend_from_slice(&[0xAB; 24]);
        assert!(Signer::from_node_account_bytes(&extended).is_ok());
    }

    #[test]
    fn node_status_tag_accepts_every_program_value() {
        let mut data = node_account_data(7);
        for tag in 0..=NODE_STATUS_MAX_TAG {
            data[NODE_STATUS_OFFSET] = tag;
            assert!(Signer::from_node_account_bytes(&data).is_ok(), "tag {tag}");
        }
        for tag in NODE_STATUS_MAX_TAG + 1..=255u8 {
            data[NODE_STATUS_OFFSET] = tag;
            assert!(Signer::from_node_account_bytes(&data).is_err(), "tag {tag}",);
        }
    }

    #[test]
    fn verify_attestation_accounts_accepts_fixture() {
        let mut accounts = Accounts::new();
        let (registry, nodes) = accounts.split();
        verify_attestation_accounts(&fixture_attestation(), &registry, &nodes, &PROGRAM_ID)
            .expect("account-path fixture must verify");
    }

    #[test]
    fn verify_attestation_accounts_rejects_version_mismatch() {
        let mut accounts = Accounts::with_version(REGISTRY_VERSION + 1);
        let (registry, nodes) = accounts.split();
        assert_eq!(
            verify_attestation_accounts(&fixture_attestation(), &registry, &nodes, &PROGRAM_ID)
                .unwrap_err(),
            AccountError::Attestation(AttestationError::InvalidRegistryVersion)
        );
    }

    #[test]
    fn verify_attestation_accounts_rejects_node_order_swap() {
        let mut accounts = Accounts::new();
        accounts.node_keys.swap(0, 1);
        accounts.node_data.swap(0, 1);
        let (registry, nodes) = accounts.split();
        assert_eq!(
            verify_attestation_accounts(&fixture_attestation(), &registry, &nodes, &PROGRAM_ID)
                .unwrap_err(),
            AccountError::Attestation(AttestationError::MissingSignerAccount)
        );
    }

    #[test]
    fn verify_attestation_accounts_rejects_missing_node_account() {
        let mut accounts = Accounts::new();
        accounts.node_keys.pop();
        accounts.node_data.pop();
        accounts.node_lamports.pop();
        let (registry, nodes) = accounts.split();
        assert_eq!(
            verify_attestation_accounts(&fixture_attestation(), &registry, &nodes, &PROGRAM_ID)
                .unwrap_err(),
            AccountError::Attestation(AttestationError::MissingSignerAccount)
        );
    }

    #[test]
    fn verify_attestation_accounts_rejects_unregistered_signer() {
        let mut accounts = Accounts::new();
        accounts.node_keys[0] = node_pda(50).0;
        accounts.node_data[0] = {
            let (_, bump) = node_pda(50);
            let (x, y) = PUBKEYS[0];
            let mut data = vec![0u8; NODE_ACCOUNT_LEN];
            fill_node_account(&mut data, &node_owner(50), &x, &y, 0, bump);
            data
        };
        let (registry, nodes) = accounts.split();
        assert_eq!(
            verify_attestation_accounts(&fixture_attestation(), &registry, &nodes, &PROGRAM_ID)
                .unwrap_err(),
            AccountError::Attestation(AttestationError::MissingSignerAccount)
        );
    }

    #[test]
    fn verify_attestation_accounts_rejects_tampered_value() {
        let mut accounts = Accounts::new();
        let mut attestation = fixture_attestation();
        attestation.payload.value[31] ^= 0x01;
        let (registry, nodes) = accounts.split();
        assert_eq!(
            verify_attestation_accounts(&attestation, &registry, &nodes, &PROGRAM_ID).unwrap_err(),
            AccountError::Attestation(AttestationError::InvalidAggregateSignature)
        );
    }

    #[test]
    fn verify_aggregate_over_hash_accounts_roundtrip() {
        let mut accounts = Accounts::new();
        let attestation = fixture_attestation();
        let message_hash =
            compute_message_hash(&attestation.payload, attestation.signature.signers_bitmap);
        let (registry, nodes) = accounts.split();

        assert!(verify_aggregate_over_hash_accounts(
            &registry,
            attestation.signature,
            &message_hash,
            REGISTRY_VERSION,
            &nodes,
            &PROGRAM_ID,
        )
        .expect("dispute path must run"));
    }

    #[test]
    fn verify_aggregate_over_hash_accounts_reports_invalid_signature() {
        let mut accounts = Accounts::new();
        let attestation = fixture_attestation();
        let mut message_hash =
            compute_message_hash(&attestation.payload, attestation.signature.signers_bitmap);
        message_hash[0] ^= 0xff;
        let (registry, nodes) = accounts.split();

        assert!(!verify_aggregate_over_hash_accounts(
            &registry,
            attestation.signature,
            &message_hash,
            REGISTRY_VERSION,
            &nodes,
            &PROGRAM_ID,
        )
        .expect("dispute path must run"));
    }

    const INVALID_SCALAR: [u8; 32] = [0xFF; 32];

    #[test]
    fn malformed_node_account_errors_before_version_mismatch() {
        let mut accounts = Accounts::with_version(REGISTRY_VERSION + 1);
        accounts.node_data[0][0] ^= 0xff;
        let (registry, nodes) = accounts.split();
        assert_eq!(
            verify_attestation_accounts(&fixture_attestation(), &registry, &nodes, &PROGRAM_ID)
                .unwrap_err(),
            AccountError::InvalidNodeAccount
        );
    }

    #[test]
    fn malformed_node_account_errors_before_signer_count_mismatch() {
        let mut accounts = Accounts::new();
        accounts.node_data[0][0] ^= 0xff;
        accounts.node_keys.pop();
        accounts.node_data.pop();
        accounts.node_lamports.pop();
        let (registry, nodes) = accounts.split();
        assert_eq!(
            verify_attestation_accounts(&fixture_attestation(), &registry, &nodes, &PROGRAM_ID)
                .unwrap_err(),
            AccountError::InvalidNodeAccount
        );
    }

    #[test]
    fn dispute_path_reports_invalid_scalar_as_false() {
        let mut accounts = Accounts::new();
        let attestation = fixture_attestation();
        let message_hash =
            compute_message_hash(&attestation.payload, attestation.signature.signers_bitmap);
        let mut signature = attestation.signature;
        signature.agg_sig_s = INVALID_SCALAR;
        let (registry, nodes) = accounts.split();
        assert!(!verify_aggregate_over_hash_accounts(
            &registry,
            signature,
            &message_hash,
            REGISTRY_VERSION,
            &nodes,
            &PROGRAM_ID,
        )
        .expect("invalid scalar is a verdict, not an error"));
    }

    /// Malformed Node must error even with an invalid scalar (no slashable verdict on bad input).
    #[test]
    fn dispute_path_errors_on_malformed_node_even_with_invalid_scalar() {
        let mut accounts = Accounts::new();
        accounts.node_data[0][0] ^= 0xff;
        let attestation = fixture_attestation();
        let message_hash =
            compute_message_hash(&attestation.payload, attestation.signature.signers_bitmap);
        let mut signature = attestation.signature;
        signature.agg_sig_s = INVALID_SCALAR;
        let (registry, nodes) = accounts.split();
        assert_eq!(
            verify_aggregate_over_hash_accounts(
                &registry,
                signature,
                &message_hash,
                REGISTRY_VERSION,
                &nodes,
                &PROGRAM_ID,
            )
            .unwrap_err(),
            AccountError::InvalidNodeAccount
        );
    }

    #[test]
    fn error_codes_are_distinct_and_outside_anchor_ranges() {
        let errors = [
            AccountError::Attestation(AttestationError::InsufficientSigners),
            AccountError::AccountBorrowFailed,
            AccountError::InvalidAccountOwner,
            AccountError::InvalidRegistryAccount,
            AccountError::InvalidRegistryPda,
            AccountError::InvalidNodeAccount,
            AccountError::InvalidNodePda,
        ];
        let codes: Vec<u32> = errors.iter().map(AccountError::code).collect();
        let mut sorted = codes.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), codes.len());
        assert!(codes.iter().all(|code| *code > 100_000));

        assert_eq!(
            ProgramError::from(AccountError::InvalidNodePda),
            ProgramError::Custom(AccountError::InvalidNodePda.code())
        );
    }

    #[test]
    fn attestation_errors_convert_into_account_errors() {
        let error: AccountError = AttestationError::InsufficientSigners.into();
        assert_eq!(
            error,
            AccountError::Attestation(AttestationError::InsufficientSigners)
        );
    }
}
