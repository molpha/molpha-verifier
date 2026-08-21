//! Solana account adapters — verify straight from `&[AccountInfo]`.
//!
//! The rest of this crate is framework-agnostic: the caller reads its own accounts and passes
//! plain [`RegistryView`] / [`NodeEntry`] data in. This module is the opt-in exception. Enabled
//! with the `solana` feature, it takes the Molpha program's own `Registry` and `Node` accounts as
//! `&AccountInfo`, validates and parses them, and calls [`verify_attestation_resolved`] — so a
//! consumer can hand the verifier its accounts and be done.
//!
//! Anchor accounts are an 8-byte discriminator followed by a Borsh (or, for `zero_copy`, a
//! `repr(C)`) body, so no `anchor-lang` dependency is needed to read them. Anchor consumers pass
//! `to_account_info()`; native programs pass their `AccountInfo`s directly.
//!
//! # What is validated
//!
//! For every account, before any field is trusted:
//!
//! 1. **Owner** — `account.owner == program_id`.
//! 2. **Discriminator** — the leading 8 bytes match [`REGISTRY_DISCRIMINATOR`] /
//!    [`NODE_DISCRIMINATOR`].
//! 3. **Length** — at least [`REGISTRY_ACCOUNT_LEN`] / [`NODE_ACCOUNT_LEN`].
//! 4. **PDA** — the account key is the canonical program address for its own seeds and stored
//!    bump. This is load-bearing, not ceremony: the program also creates `Registry`-shaped
//!    accounts under other seed prefixes (benchmark fixtures), and an owner + discriminator check
//!    alone would accept them.
//!
//! Node *status* is deliberately not checked. Verification binds to an immutable,
//! version-addressed registry snapshot, so a node deactivated in a later version remains valid
//! evidence for a historical one.
//!
//! # Layout coupling
//!
//! [`NodeAccount`] mirrors the program's `Node` account and the offsets in [`RegistryAccount`]
//! mirror its `Registry` account. They are pinned to the deployed program's layout; the account
//! discriminators below fail closed if the type is renamed, and the length checks fail closed if
//! fields are removed. Appending fields stays compatible.
//!
//! # Usage
//! ```ignore
//! use molpha_verifier::solana::verify_attestation_accounts;
//!
//! // `node_accounts` are the signers' `Node` accounts in ascending signers_bitmap bit order —
//! // e.g. Anchor's `ctx.remaining_accounts`.
//! verify_attestation_accounts(
//!     &attestation,
//!     &registry_account,
//!     ctx.remaining_accounts,
//!     ctx.program_id,
//! )?;
//! ```

use core::cell::Ref;

use borsh::{BorshDeserialize, BorshSerialize};
use solana_program::{account_info::AccountInfo, program_error::ProgramError, pubkey::Pubkey};

use crate::{
    onchain::{verify_aggregate_over_hash_resolved, verify_attestation_resolved},
    state::MAX_REGISTRY_NODES,
    Attestation, AttestationError, NodeEntry, RegistryView,
};

/// `Registry` PDA seed prefix: `[REGISTRY_SEED_PREFIX, version.to_le_bytes(), [bump]]`.
pub const REGISTRY_SEED_PREFIX: &[u8] = b"molpha_registry";

/// `Node` PDA seed prefix: `[NODE_SEED_PREFIX, owner, [bump]]`.
pub const NODE_SEED_PREFIX: &[u8] = b"molpha_node";

/// Anchor account discriminator for `Registry` — `sha256("account:Registry")[..8]`.
pub const REGISTRY_DISCRIMINATOR: [u8; 8] = [47, 174, 110, 246, 184, 182, 252, 218];

/// Anchor account discriminator for `Node` — `sha256("account:Node")[..8]`.
pub const NODE_DISCRIMINATOR: [u8; 8] = [208, 53, 1, 3, 49, 122, 180, 49];

/// Length of the discriminator every Anchor account is prefixed with.
pub const DISCRIMINATOR_LEN: usize = 8;

/// Serialized length of a `Registry` account, discriminator included (`Registry::SPACE`).
pub const REGISTRY_ACCOUNT_LEN: usize = 8_208;

/// Serialized length of a `Node` account, discriminator included (`Node::SPACE`).
pub const NODE_ACCOUNT_LEN: usize = 168;

// `Registry` is `#[account(zero_copy)] #[repr(C)]`, so its body is read at fixed offsets rather
// than deserialized: `version: u32`, `node_count: u16`, `redundancy_buffer: u8`, `bump: u8`, then
// `nodes: [[u8; 32]; MAX_REGISTRY_NODES]`. Max field alignment is 4 and the header is exactly 8
// bytes, so there is no interior or trailing padding.
const REGISTRY_VERSION_OFFSET: usize = DISCRIMINATOR_LEN;
const REGISTRY_NODE_COUNT_OFFSET: usize = REGISTRY_VERSION_OFFSET + 4;
const REGISTRY_REDUNDANCY_BUFFER_OFFSET: usize = REGISTRY_NODE_COUNT_OFFSET + 2;
const REGISTRY_BUMP_OFFSET: usize = REGISTRY_REDUNDANCY_BUFFER_OFFSET + 1;
const REGISTRY_NODES_OFFSET: usize = REGISTRY_BUMP_OFFSET + 1;
const REGISTRY_NODES_LEN: usize = MAX_REGISTRY_NODES * 32;

const _: () = assert!(REGISTRY_NODES_OFFSET + REGISTRY_NODES_LEN == REGISTRY_ACCOUNT_LEN);

/// Base for [`AccountError::code`] — `0x4D4F_0000`, i.e. ASCII `"MO"` in the high half.
///
/// Deliberately outside Anchor's reserved ranges *and* its `6000+` user-error range, so mapping
/// these into a `ProgramError::Custom` never collides with a consumer's own error codes.
pub const ERROR_CODE_BASE: u32 = 0x4D4F_0000;

/// Failure to turn accounts into verified attestation inputs.
///
/// Wraps [`AttestationError`] so a single `?` covers both account I/O and cryptographic
/// verification. Downstream programs typically map this at the instruction boundary.
#[cfg_attr(feature = "thiserror", derive(thiserror::Error))]
#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub enum AccountError {
    /// Verification ran and failed. See the wrapped [`AttestationError`].
    #[cfg_attr(feature = "thiserror", error("{0}"))]
    Attestation(AttestationError),
    /// An account's data is already mutably borrowed elsewhere.
    #[cfg_attr(feature = "thiserror", error("account data is already borrowed"))]
    AccountBorrowFailed,
    /// An account is not owned by the Molpha program.
    #[cfg_attr(feature = "thiserror", error("account is not owned by the program"))]
    InvalidAccountOwner,
    /// The registry account's discriminator or length does not match `Registry`.
    #[cfg_attr(
        feature = "thiserror",
        error("registry account discriminator or length mismatch")
    )]
    InvalidRegistryAccount,
    /// The registry account is not the canonical PDA for its version and stored bump.
    #[cfg_attr(
        feature = "thiserror",
        error("registry account is not the canonical PDA for its version")
    )]
    InvalidRegistryPda,
    /// A node account's discriminator, length, or Borsh body does not match `Node`.
    #[cfg_attr(
        feature = "thiserror",
        error("node account discriminator, length, or body mismatch")
    )]
    InvalidNodeAccount,
    /// A node account is not the canonical PDA for its owner and stored bump.
    #[cfg_attr(
        feature = "thiserror",
        error("node account is not the canonical PDA for its owner")
    )]
    InvalidNodePda,
}

impl AccountError {
    /// Stable numeric code, [`ERROR_CODE_BASE`]-offset. Wrapped [`AttestationError`]s collapse to
    /// a single code; match on the variant if the inner reason matters.
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

/// Lifecycle state of a registered node. Mirrors the program's `NodeStatus`.
#[derive(BorshSerialize, BorshDeserialize, Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum NodeStatus {
    #[default]
    Active,
    Deactivated,
    /// Evicted by a punishment with `MembershipAction::Freeze`; restorable via `reinstate_node`.
    Frozen,
    /// Evicted by a punishment with `MembershipAction::Tombstone`. Terminal.
    Tombstoned,
}

/// Parsed body of a `Node` account — a read-only mirror of the program's `Node`.
///
/// Field order and types must match the program exactly; Borsh is positional. Only `owner`
/// (for the PDA check) and the secp256k1 coordinates are used by verification, but decoding the
/// whole body validates the account instead of trusting offsets — a malformed `status` byte or a
/// truncated tail is rejected here rather than silently read past.
#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, PartialEq, Eq)]
pub struct NodeAccount {
    pub owner: [u8; 32],
    pub secp256k1_pubkey_x: [u8; 32],
    pub secp256k1_pubkey_y: [u8; 32],
    pub status: NodeStatus,
    pub ip: [u8; 4],
    pub port: u16,
    pub locked_amount: u64,
    pub claimable_rewards: u64,
    pub registered_at: i64,
    pub deactivated_at: i64,
    pub withdrawable_at: i64,
    /// Unix timestamp a `Frozen` node becomes permissionlessly reinstatable. Unused otherwise.
    pub frozen_until: i64,
    /// Unix timestamp of the most recent punishment, or `0` if never punished.
    pub punished_at: i64,
    pub bump: u8,
}

impl NodeAccount {
    /// Parse raw account data (discriminator included) into a `Node` body.
    ///
    /// Checks length and discriminator, then Borsh-decodes. Trailing bytes beyond the known
    /// fields are ignored, so a program that appends fields stays compatible.
    pub fn parse(data: &[u8]) -> Result<Self, AccountError> {
        if data.len() < NODE_ACCOUNT_LEN || data[..DISCRIMINATOR_LEN] != NODE_DISCRIMINATOR {
            return Err(AccountError::InvalidNodeAccount);
        }
        Self::deserialize(&mut &data[DISCRIMINATOR_LEN..])
            .map_err(|_| AccountError::InvalidNodeAccount)
    }

    /// Canonical `Node` PDA for this body's `owner` and stored `bump`.
    pub fn expected_pda(&self, program_id: &Pubkey) -> Result<Pubkey, AccountError> {
        Pubkey::create_program_address(
            &[NODE_SEED_PREFIX, self.owner.as_ref(), &[self.bump]],
            program_id,
        )
        .map_err(|_| AccountError::InvalidNodePda)
    }
}

/// A validated, borrowed `Registry` account.
///
/// Holds the account-data borrow for its lifetime so [`RegistryView`] can point straight at the
/// 8 KB `nodes` array without copying it.
pub struct RegistryAccount<'a> {
    key: Pubkey,
    data: Ref<'a, [u8]>,
}

impl<'a> RegistryAccount<'a> {
    /// Borrow, validate, and bind a `Registry` account.
    ///
    /// Runs the full owner / discriminator / length / PDA check set described in the module docs.
    pub fn load(account: &'a AccountInfo<'_>, program_id: &Pubkey) -> Result<Self, AccountError> {
        if account.owner != program_id {
            return Err(AccountError::InvalidAccountOwner);
        }
        let data = account
            .try_borrow_data()
            .map_err(|_| AccountError::AccountBorrowFailed)?;
        // Narrow `Ref<&mut [u8]>` to `Ref<[u8]>` so the guard needs only one lifetime parameter.
        let data = Ref::map(data, |bytes| &**bytes);

        if data.len() < REGISTRY_ACCOUNT_LEN || data[..DISCRIMINATOR_LEN] != REGISTRY_DISCRIMINATOR
        {
            return Err(AccountError::InvalidRegistryAccount);
        }

        let registry = Self {
            key: *account.key,
            data,
        };
        if registry.expected_pda(program_id)? != registry.key {
            return Err(AccountError::InvalidRegistryPda);
        }
        Ok(registry)
    }

    /// Canonical `Registry` PDA for this account's version and stored bump.
    pub fn expected_pda(&self, program_id: &Pubkey) -> Result<Pubkey, AccountError> {
        Pubkey::create_program_address(
            &[
                REGISTRY_SEED_PREFIX,
                self.version().to_le_bytes().as_ref(),
                &[self.bump()],
            ],
            program_id,
        )
        .map_err(|_| AccountError::InvalidRegistryPda)
    }

    /// The account's address.
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

    /// The full ordered node-address array. Only `[..node_count()]` is populated.
    pub fn nodes(&self) -> &[[u8; 32]] {
        let bytes = &self.data[REGISTRY_NODES_OFFSET..REGISTRY_NODES_OFFSET + REGISTRY_NODES_LEN];
        // SAFETY: `bytes` is exactly `MAX_REGISTRY_NODES * 32` bytes (the slice bounds are
        // constants and `load` checked `data.len() >= REGISTRY_ACCOUNT_LEN`). `[u8; 32]` has
        // alignment 1 and no invalid bit patterns, so any byte pointer is a valid, correctly
        // aligned `*const [u8; 32]`. The returned slice borrows `self`, so it cannot outlive the
        // account-data guard.
        unsafe {
            core::slice::from_raw_parts(bytes.as_ptr().cast::<[u8; 32]>(), MAX_REGISTRY_NODES)
        }
    }

    /// Framework-agnostic view for the resolution / verification helpers.
    pub fn view(&self) -> RegistryView<'_> {
        RegistryView {
            version: self.version(),
            node_count: self.node_count(),
            redundancy_buffer: self.redundancy_buffer(),
            nodes: self.nodes(),
        }
    }
}

/// Header fields only — the 8 KB `nodes` array is elided.
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
    let node = NodeAccount::parse(&data)?;
    if node.expected_pda(program_id)? != *account.key {
        return Err(AccountError::InvalidNodePda);
    }
    Ok(NodeEntry {
        account: account.key.to_bytes(),
        x: node.secp256k1_pubkey_x,
        y: node.secp256k1_pubkey_y,
    })
}

/// Validate and parse signer `Node` accounts into [`NodeEntry`]s.
///
/// Accounts must be in ascending `signers_bitmap` bit order — Anchor's `remaining_accounts` in the
/// order the client built them. Slot binding (`entry.account == registry.nodes[bit]`) happens in
/// [`verify_attestation_accounts`]; this function only validates and decodes.
pub fn resolve_nodes(
    accounts: &[AccountInfo<'_>],
    program_id: &Pubkey,
) -> Result<Vec<NodeEntry>, AccountError> {
    accounts
        .iter()
        .map(|account| resolve_node(account, program_id))
        .collect()
}

/// Verify an attestation directly from its `Registry` and signer `Node` accounts.
///
/// `node_accounts` are the signers' `Node` accounts in ascending `signers_bitmap` bit order.
/// Requires `attestation.payload.registry_version == registry.version`.
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

/// Verify an aggregate signature over an arbitrary message hash from accounts (dispute / slash).
///
/// `Ok(true)` = valid, `Ok(false)` = invalid (slashable), `Err` = malformed accounts or input.
#[allow(clippy::too_many_arguments)]
pub fn verify_aggregate_over_hash_accounts(
    registry_account: &AccountInfo<'_>,
    registry_version: u32,
    signers_bitmap: &[u8; 32],
    agg_sig_s: &[u8; 32],
    commitment_addr: &[u8; 20],
    message_hash: &[u8; 32],
    node_accounts: &[AccountInfo<'_>],
    program_id: &Pubkey,
) -> Result<bool, AccountError> {
    let registry = RegistryAccount::load(registry_account, program_id)?;
    let entries = resolve_nodes(node_accounts, program_id)?;
    Ok(verify_aggregate_over_hash_resolved(
        &registry.view(),
        registry_version,
        signers_bitmap,
        agg_sig_s,
        commitment_addr,
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
    use libsecp256k1::{PublicKey, PublicKeyFormat};

    const PROGRAM_ID: Pubkey = Pubkey::new_from_array([7u8; 32]);

    fn pubkey_xy(compressed: &[u8; 33]) -> ([u8; 32], [u8; 32]) {
        let pk = PublicKey::parse_slice(compressed, Some(PublicKeyFormat::Compressed))
            .expect("fixture pubkey must be a valid curve point");
        let full = pk.serialize();
        (
            full[1..33].try_into().unwrap(),
            full[33..65].try_into().unwrap(),
        )
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

    /// Serialized `Node` account for fixture node `index`, at its canonical PDA.
    fn node_account_data(index: usize) -> Vec<u8> {
        let (_, bump) = node_pda(index);
        let (x, y) = pubkey_xy(&PUBKEYS[index]);
        let node = NodeAccount {
            owner: node_owner(index),
            secp256k1_pubkey_x: x,
            secp256k1_pubkey_y: y,
            status: NodeStatus::Active,
            ip: [127, 0, 0, 1],
            port: 8080,
            locked_amount: 100,
            claimable_rewards: 0,
            registered_at: 1,
            deactivated_at: 0,
            withdrawable_at: 0,
            frozen_until: 0,
            punished_at: 0,
            bump,
        };
        let mut data = NODE_DISCRIMINATOR.to_vec();
        node.serialize(&mut data).expect("serialize node");
        assert_eq!(data.len(), NODE_ACCOUNT_LEN);
        data
    }

    /// Serialized `Registry` account holding the 12 fixture node PDAs, at its canonical PDA.
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
                commitment_addr: COMMITMENT,
                signers_bitmap: SIGNERS_BITMAP,
            },
        }
    }

    fn signer_indices() -> Vec<usize> {
        let mut indices = Vec::new();
        for_each_set_bit(&SIGNERS_BITMAP, |bit| indices.push(bit));
        indices
    }

    /// Owned backing storage for a set of `AccountInfo`s.
    ///
    /// `AccountInfo` borrows its lamports and data mutably, so the buffers must outlive it and be
    /// handed out one `&mut` at a time — hence the two-step build/borrow.
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

        /// Split borrow so the registry and node `AccountInfo`s can coexist.
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

    // ---- layout constants -------------------------------------------------

    #[test]
    fn discriminators_match_anchor_derivation() {
        // Anchor: sha256("account:<Name>")[..8]. Recomputed here so a rename in the program is
        // caught by a failing IDL diff rather than a silently-wrong constant.
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
    fn node_status_variants_encode_as_anchor_tags() {
        for (status, tag) in [
            (NodeStatus::Active, 0u8),
            (NodeStatus::Deactivated, 1),
            (NodeStatus::Frozen, 2),
            (NodeStatus::Tombstoned, 3),
        ] {
            let mut encoded = Vec::new();
            status.serialize(&mut encoded).unwrap();
            assert_eq!(encoded, vec![tag]);
        }
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
        // Slots past node_count stay zeroed.
        assert_eq!(nodes[REGISTERED_NODE_COUNT as usize], [0u8; 32]);
    }

    // ---- registry account -------------------------------------------------

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
    fn registry_load_rejects_non_canonical_pda() {
        // A program-owned, correctly-discriminated Registry sitting at some other address — the
        // shape the benchmark-seed registries have.
        let mut accounts = Accounts::new();
        accounts.registry_key = Pubkey::new_from_array([0x33u8; 32]);
        let info = accounts.registry();
        assert_eq!(
            RegistryAccount::load(&info, &PROGRAM_ID).unwrap_err(),
            AccountError::InvalidRegistryPda
        );
    }

    #[test]
    fn registry_load_rejects_tampered_bump() {
        let mut accounts = Accounts::new();
        accounts.registry_data[REGISTRY_BUMP_OFFSET] =
            accounts.registry_data[REGISTRY_BUMP_OFFSET].wrapping_sub(1);
        let info = accounts.registry();
        assert_eq!(
            RegistryAccount::load(&info, &PROGRAM_ID).unwrap_err(),
            AccountError::InvalidRegistryPda
        );
    }

    #[test]
    fn registry_load_rejects_version_swap() {
        // Rewriting the version re-seeds the PDA, so a snapshot cannot be relabelled in place.
        let mut accounts = Accounts::new();
        accounts.registry_data[REGISTRY_VERSION_OFFSET..REGISTRY_VERSION_OFFSET + 4]
            .copy_from_slice(&(REGISTRY_VERSION + 1).to_le_bytes());
        let info = accounts.registry();
        assert_eq!(
            RegistryAccount::load(&info, &PROGRAM_ID).unwrap_err(),
            AccountError::InvalidRegistryPda
        );
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

    // ---- node accounts ----------------------------------------------------

    #[test]
    fn resolve_nodes_returns_entries_in_account_order() {
        let mut accounts = Accounts::new();
        let infos = accounts.nodes();
        let entries = resolve_nodes(&infos, &PROGRAM_ID).expect("resolve nodes");

        let indices = signer_indices();
        assert_eq!(entries.len(), indices.len());
        for (entry, index) in entries.iter().zip(indices) {
            let (x, y) = pubkey_xy(&PUBKEYS[index]);
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
        // `status` sits right after the discriminator, owner, and both coordinates.
        accounts.node_data[0][DISCRIMINATOR_LEN + 96] = 9;
        let infos = accounts.nodes();
        assert_eq!(
            resolve_nodes(&infos, &PROGRAM_ID).unwrap_err(),
            AccountError::InvalidNodeAccount
        );
    }

    #[test]
    fn resolve_nodes_rejects_non_canonical_pda() {
        let mut accounts = Accounts::new();
        accounts.node_keys[2] = Pubkey::new_from_array([0x44u8; 32]);
        let infos = accounts.nodes();
        assert_eq!(
            resolve_nodes(&infos, &PROGRAM_ID).unwrap_err(),
            AccountError::InvalidNodePda
        );
    }

    #[test]
    fn resolve_nodes_rejects_swapped_owner_field() {
        // Repointing `owner` re-seeds the PDA, so one node's key cannot host another's identity.
        let mut accounts = Accounts::new();
        let other_owner = node_owner(1);
        accounts.node_data[0][DISCRIMINATOR_LEN..DISCRIMINATOR_LEN + 32]
            .copy_from_slice(&other_owner);
        let infos = accounts.nodes();
        assert_eq!(
            resolve_nodes(&infos, &PROGRAM_ID).unwrap_err(),
            AccountError::InvalidNodePda
        );
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
        // A node deactivated in a later version is still valid evidence for this snapshot.
        let mut accounts = Accounts::new();
        accounts.node_data[0][DISCRIMINATOR_LEN + 96] = NodeStatus::Tombstoned as u8;
        let infos = accounts.nodes();
        assert!(resolve_nodes(&infos, &PROGRAM_ID).is_ok());
    }

    #[test]
    fn node_account_roundtrips_through_borsh() {
        let data = node_account_data(3);
        let node = NodeAccount::parse(&data).expect("parse node");
        assert_eq!(node.owner, node_owner(3));
        assert_eq!(node.status, NodeStatus::Active);
        assert_eq!(node.port, 8080);
        assert_eq!(node.bump, node_pda(3).1);

        let mut reencoded = NODE_DISCRIMINATOR.to_vec();
        node.serialize(&mut reencoded).unwrap();
        assert_eq!(reencoded, data);
    }

    // ---- end-to-end -------------------------------------------------------

    #[test]
    fn verify_attestation_accounts_accepts_fixture() {
        let mut accounts = Accounts::new();
        let (registry, nodes) = accounts.split();
        verify_attestation_accounts(&fixture_attestation(), &registry, &nodes, &PROGRAM_ID)
            .expect("account-path fixture must verify");
    }

    #[test]
    fn verify_attestation_accounts_rejects_version_mismatch() {
        // A genuine, canonically-addressed registry — just the wrong snapshot.
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
        // Slot binding is positional: entry `n` must be `registry.nodes[nth set bit]`.
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
        // A well-formed node at its canonical PDA, but not in this registry snapshot.
        let mut accounts = Accounts::new();
        accounts.node_keys[0] = node_pda(50).0;
        accounts.node_data[0] = {
            let (_, bump) = node_pda(50);
            let (x, y) = pubkey_xy(&PUBKEYS[0]);
            let node = NodeAccount {
                owner: node_owner(50),
                secp256k1_pubkey_x: x,
                secp256k1_pubkey_y: y,
                status: NodeStatus::Active,
                ip: [127, 0, 0, 1],
                port: 8080,
                locked_amount: 100,
                claimable_rewards: 0,
                registered_at: 1,
                deactivated_at: 0,
                withdrawable_at: 0,
                frozen_until: 0,
                punished_at: 0,
                bump,
            };
            let mut data = NODE_DISCRIMINATOR.to_vec();
            node.serialize(&mut data).unwrap();
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
            REGISTRY_VERSION,
            &attestation.signature.signers_bitmap,
            &attestation.signature.agg_sig_s,
            &attestation.signature.commitment_addr,
            &message_hash,
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
            REGISTRY_VERSION,
            &attestation.signature.signers_bitmap,
            &attestation.signature.agg_sig_s,
            &attestation.signature.commitment_addr,
            &message_hash,
            &nodes,
            &PROGRAM_ID,
        )
        .expect("dispute path must run"));
    }

    // ---- errors -----------------------------------------------------------

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
