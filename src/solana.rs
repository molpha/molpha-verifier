//! Solana account adapters — verify from `&[AccountInfo]`.
//!
//! Opt-in (`solana` feature): validates Molpha `Registry` / `Node` accounts and calls
//! [`crate::verify_attestation_resolved`]. Reads Anchor layouts (8-byte discriminator + body)
//! without depending on `anchor-lang`.
//!
//! # Checks
//!
//! Before trusting account data:
//! 1. **Owner** — `account.owner == program_id`
//! 2. **Discriminator** — matches [`REGISTRY_DISCRIMINATOR`] / [`NODE_DISCRIMINATOR`]
//! 3. **Length** — at least [`REGISTRY_ACCOUNT_LEN`] / [`NODE_ACCOUNT_LEN`]
//! 4. **Well-formedness** — pubkey `(x, y)` at fixed offsets
//!
//! Node status is not consulted during verification; historical snapshots may still use
//! deactivated nodes.
//! Body fields are read at fixed offsets pinned to the program layout. Discriminator / length
//! checks fail closed on rename / truncation; appending fields stays compatible.
//!
//! # Usage
//! ```ignore
//! use molpha_verifier::solana::verify_attestation;
//!
//! // `node_accounts`: signer Node accounts in ascending signers_bitmap bit order.
//! verify_attestation(
//!     &attestation,
//!     &registry_account,
//!     ctx.remaining_accounts,
//! )?;
//! ```

use core::cell::Ref;

use solana_account_info::AccountInfo;
use solana_program_error::ProgramError;
use solana_pubkey::Pubkey;

use crate::{
    onchain::{resolve_intersected_signers, resolve_signers, IntersectedResolution},
    state::{SignerXy, MAX_REGISTRY_NODES},
    verify::{
        verify, verify_aggregate_over_hash, verify_aggregate_over_hash_with_coalition_key,
        verify_with_coalition_key,
    },
    Attestation, AttestationError, CoalitionKey, NodeEntry, RegistryView, SchnorrSignature,
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
pub const NODE_ACCOUNT_LEN: usize = 152;

pub const PROGRAM_ID: Pubkey =
    Pubkey::from_str_const("MoLFnEbuMS5gWnXNfUMLAYSqRM3eQZKWRzjeMQfqbT3");

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
pub const NODE_OWNER_OFFSET: usize = DISCRIMINATOR_LEN;
pub const NODE_PUBKEY_X_OFFSET: usize = NODE_OWNER_OFFSET + 32;
pub const NODE_PUBKEY_Y_OFFSET: usize = NODE_PUBKEY_X_OFFSET + 32;
pub const NODE_STATUS_OFFSET: usize = NODE_PUBKEY_Y_OFFSET + 32;
// ip(4) + port(2) + five 8-byte trailing fields + bump(1)
pub const NODE_BUMP_OFFSET: usize = NODE_STATUS_OFFSET + 1 + 4 + 2 + 5 * 8;

const _: () = assert!(NODE_BUMP_OFFSET + 1 == NODE_ACCOUNT_LEN);

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

/// Preserve verifier program-error codes while allowing `?` in Anchor handlers.
#[cfg(feature = "anchor")]
impl From<AccountError> for anchor_lang::error::Error {
    fn from(error: AccountError) -> Self {
        ProgramError::from(error).into()
    }
}

/// Validated, borrowed `Registry` account (holds the data borrow for zero-copy `nodes`).
pub struct RegistryAccount<'a> {
    key: Pubkey,
    data: Ref<'a, [u8]>,
}

impl<'a> RegistryAccount<'a> {
    /// Borrow and validate a `Registry` account (owner / discriminator / length).
    pub fn load(account: &'a AccountInfo<'_>) -> Result<Self, AccountError> {
        if *account.owner != PROGRAM_ID {
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

        Ok(Self {
            key: *account.key,
            data,
        })
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

    pub fn bytes(&self) -> &[u8] {
        &self.data
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

    pub fn node_key(&self, index: usize) -> Result<Pubkey, AccountError> {
        Ok(Pubkey::new_from_array(self.nodes()[index]))
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

impl NodeEntry {
    pub fn load(account: &AccountInfo<'_>) -> Result<Self, AccountError> {
        if *account.owner != PROGRAM_ID {
            return Err(AccountError::InvalidAccountOwner);
        }

        let data = account
            .try_borrow_data()
            .map_err(|_| AccountError::AccountBorrowFailed)?;
        let data = Ref::map(data, |bytes| &**bytes);

        if data.len() < NODE_ACCOUNT_LEN || data[..DISCRIMINATOR_LEN] != NODE_DISCRIMINATOR {
            return Err(AccountError::InvalidNodeAccount);
        }

        let x = read_32(&data, NODE_PUBKEY_X_OFFSET);
        let y = read_32(&data, NODE_PUBKEY_Y_OFFSET);

        let node = Self {
            account: account.key.to_bytes(),
            x,
            y,
        };
        Ok(node)
    }
}

#[inline]
fn read_32(data: &[u8], offset: usize) -> [u8; 32] {
    data[offset..offset + 32]
        .try_into()
        .expect("length checked by caller")
}

pub fn resolve_signers_accounts(
    accounts: &[AccountInfo],
    registry_account: &AccountInfo<'_>,
    signers_bitmap: &[u8; 32],
) -> Result<Vec<SignerXy>, AccountError> {
    let registry = RegistryAccount::load(registry_account)?;
    resolve_signers_accounts_core(accounts, &registry.view(), signers_bitmap)
}

pub fn resolve_intersected_signers_accounts(
    accounts: &[AccountInfo],
    registry_account: &AccountInfo<'_>,
    bitmap_a: &[u8; 32],
    bitmap_b: &[u8; 32],
) -> Result<IntersectedResolution, AccountError> {
    let registry = RegistryAccount::load(registry_account)?;
    let view = registry.view();
    let nodes = accounts
        .iter()
        .map(|account| NodeEntry::load(account))
        .collect::<Result<Vec<NodeEntry>, AccountError>>()?;
    Ok(resolve_intersected_signers(
        &nodes, &view, bitmap_a, bitmap_b,
    )?)
}

fn resolve_signers_accounts_core(
    accounts: &[AccountInfo],
    registry: &RegistryView<'_>,
    signers_bitmap: &[u8; 32],
) -> Result<Vec<SignerXy>, AccountError> {
    let nodes = accounts
        .iter()
        .map(|account| NodeEntry::load(account))
        .collect::<Result<Vec<NodeEntry>, AccountError>>()?;
    let signers = resolve_signers(&nodes, registry, signers_bitmap)?;
    Ok(signers)
}

/// Verify an attestation from its `Registry` and signer `Node` accounts.
pub fn verify_attestation(
    attestation: &Attestation,
    registry_account: &AccountInfo<'_>,
    node_accounts: &[AccountInfo<'_>],
) -> Result<(), AccountError> {
    verify_attestation_inner(attestation, registry_account, node_accounts, None)
}

/// [`verify_attestation`] with the affine coalition key supplied instead of computed (see
/// [`crate::verify_with_coalition_key`]).
///
/// Replaces the software field inversion of the coalition key with a few field multiplications.
/// The key is typically carried in instruction data; it is not part of the signed message.
pub fn verify_attestation_with_coalition_key(
    attestation: &Attestation,
    registry_account: &AccountInfo<'_>,
    node_accounts: &[AccountInfo<'_>],
    coalition_key: &CoalitionKey,
) -> Result<(), AccountError> {
    verify_attestation_inner(
        attestation,
        registry_account,
        node_accounts,
        Some(coalition_key),
    )
}

#[inline(always)]
fn verify_attestation_inner(
    attestation: &Attestation,
    registry_account: &AccountInfo<'_>,
    node_accounts: &[AccountInfo<'_>],
    coalition_key: Option<&CoalitionKey>,
) -> Result<(), AccountError> {
    let registry = RegistryAccount::load(registry_account)?;
    let view = registry.view();

    let ordered_signers =
        resolve_signers_accounts_core(node_accounts, &view, &attestation.signature.signers_bitmap)?;

    if attestation.payload.registry_version != view.version {
        return Err(AccountError::Attestation(
            AttestationError::InvalidRegistryVersion,
        ));
    }

    Ok(match coalition_key {
        Some(key) => verify_with_coalition_key(attestation, &ordered_signers, &view, key),
        None => verify(attestation, &ordered_signers, &view),
    }?)
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
) -> Result<bool, AccountError> {
    verify_aggregate_over_hash_accounts_inner(
        registry_account,
        signature,
        message_hash,
        registry_version,
        node_accounts,
        None,
    )
}

/// [`verify_aggregate_over_hash_accounts`] with the affine coalition key supplied (see
/// [`crate::verify_aggregate_over_hash_with_coalition_key`]). A wrong key is an `Err`, not an
/// `Ok(false)` verdict.
pub fn verify_aggregate_over_hash_accounts_with_coalition_key(
    registry_account: &AccountInfo<'_>,
    signature: SchnorrSignature,
    message_hash: &[u8; 32],
    registry_version: u32,
    node_accounts: &[AccountInfo<'_>],
    coalition_key: &CoalitionKey,
) -> Result<bool, AccountError> {
    verify_aggregate_over_hash_accounts_inner(
        registry_account,
        signature,
        message_hash,
        registry_version,
        node_accounts,
        Some(coalition_key),
    )
}

#[inline(always)]
fn verify_aggregate_over_hash_accounts_inner(
    registry_account: &AccountInfo<'_>,
    signature: SchnorrSignature,
    message_hash: &[u8; 32],
    registry_version: u32,
    node_accounts: &[AccountInfo<'_>],
    coalition_key: Option<&CoalitionKey>,
) -> Result<bool, AccountError> {
    let registry = RegistryAccount::load(registry_account)?;
    let view = registry.view();
    if view.version != registry_version {
        return Err(AccountError::InvalidRegistryAccount);
    }
    let ordered_signers =
        resolve_signers_accounts_core(node_accounts, &view, &signature.signers_bitmap)?;
    let (s, commitment) = (&signature.agg_sig_s, &signature.commitment);
    Ok(match coalition_key {
        Some(key) => verify_aggregate_over_hash_with_coalition_key(
            s,
            commitment,
            message_hash,
            &ordered_signers,
            key,
        ),
        None => verify_aggregate_over_hash(s, commitment, message_hash, &ordered_signers),
    }?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixtures::{
        CANONICAL_TIMESTAMP, COMMITMENT, PUBKEYS, REDUNDANCY_BUFFER, REGISTERED_NODE_COUNT,
        REGISTRY_VERSION, S, SIGNATURES_REQUIRED, SIGNERS_BITMAP, SOURCE_ID, VALUE,
    };
    use crate::message::compute_message_hash;
    use crate::payload::{AttestationPayload, SchnorrSignature};

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
        use crate::bitmap::{for_each_set_bit, Bitmap};
        let mut indices = Vec::new();
        for_each_set_bit(Bitmap::load(&SIGNERS_BITMAP), |bit| {
            indices.push(bit);
            Ok::<(), std::convert::Infallible>(())
        })
        .unwrap();
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
        assert_eq!(NODE_ACCOUNT_LEN, DISCRIMINATOR_LEN + 144);
    }

    #[test]
    fn nodes_slice_matches_raw_account_bytes() {
        let mut accounts = Accounts::new();
        let info = accounts.registry();
        let registry = RegistryAccount::load(&info).expect("load registry");
        let view = registry.view();
        let data = registry.bytes();

        assert_eq!(view.nodes.len(), MAX_REGISTRY_NODES);
        for (index, node) in view.nodes.iter().enumerate() {
            let offset = REGISTRY_NODES_OFFSET + index * 32;
            assert_eq!(&node[..], &data[offset..offset + 32]);
        }
        for (index, node) in view
            .nodes
            .iter()
            .enumerate()
            .take(REGISTERED_NODE_COUNT as usize)
        {
            assert_eq!(*node, node_pda(index).0.to_bytes());
        }
        assert_eq!(view.nodes[REGISTERED_NODE_COUNT as usize], [0u8; 32]);
    }

    #[test]
    fn node_account_framing_checks() {
        let full = node_account_data(3);
        let key = node_pda(3).0;
        let mut lamports = 1u64;

        for len in [0usize, 1, DISCRIMINATOR_LEN, NODE_ACCOUNT_LEN - 1] {
            let mut short = full[..len].to_vec();
            let info = AccountInfo::new(
                &key,
                false,
                false,
                &mut lamports,
                &mut short,
                &PROGRAM_ID,
                false,
            );
            assert_eq!(
                NodeEntry::load(&info).unwrap_err(),
                AccountError::InvalidNodeAccount,
                "truncation to {len} must be rejected",
            );
        }

        let mut wrong_discriminator = full.clone();
        wrong_discriminator[0] ^= 0xff;
        let info = AccountInfo::new(
            &key,
            false,
            false,
            &mut lamports,
            &mut wrong_discriminator,
            &PROGRAM_ID,
            false,
        );
        assert_eq!(
            NodeEntry::load(&info).unwrap_err(),
            AccountError::InvalidNodeAccount
        );

        let mut extended = full;
        extended.extend_from_slice(&[0xAB; 24]);
        let info = AccountInfo::new(
            &key,
            false,
            false,
            &mut lamports,
            &mut extended,
            &PROGRAM_ID,
            false,
        );
        NodeEntry::load(&info).expect("trailing bytes are allowed");
    }

    #[test]
    fn node_status_tag_is_not_consulted() {
        let mut data = node_account_data(7);
        let key = node_pda(7).0;
        let mut lamports = 1u64;
        for tag in [0u8, 3, 255] {
            data[NODE_STATUS_OFFSET] = tag;
            let info = AccountInfo::new(
                &key,
                false,
                false,
                &mut lamports,
                &mut data,
                &PROGRAM_ID,
                false,
            );
            NodeEntry::load(&info)
                .unwrap_or_else(|_| panic!("status tag {tag} must not block load"));
        }
    }

    #[test]
    fn verify_attestation_accounts_accepts_fixture() {
        let mut accounts = Accounts::new();
        let (registry, nodes) = accounts.split();
        verify_attestation(&fixture_attestation(), &registry, &nodes)
            .expect("account-path fixture must verify");
    }

    #[test]
    fn verify_attestation_with_coalition_key_accepts_fixture_and_rejects_bad_key() {
        let mut accounts = Accounts::new();
        let (registry, nodes) = accounts.split();
        let attestation = fixture_attestation();
        let signers =
            resolve_signers_accounts(&nodes, &registry, &attestation.signature.signers_bitmap)
                .unwrap();
        let key = crate::coalition_key(&signers).unwrap();
        verify_attestation_with_coalition_key(&attestation, &registry, &nodes, &key)
            .expect("keyed account path must verify");

        let mut bad = key;
        bad.x[0] ^= 0x01;
        assert_eq!(
            verify_attestation_with_coalition_key(&attestation, &registry, &nodes, &bad)
                .unwrap_err(),
            AccountError::Attestation(AttestationError::InvalidCoalitionKey)
        );
    }

    #[test]
    fn verify_aggregate_over_hash_accounts_with_coalition_key_roundtrip() {
        let mut accounts = Accounts::new();
        let attestation = fixture_attestation();
        let message_hash = attestation.message_hash();
        let (registry, nodes) = accounts.split();
        let signers =
            resolve_signers_accounts(&nodes, &registry, &attestation.signature.signers_bitmap)
                .unwrap();
        let key = crate::coalition_key(&signers).unwrap();

        assert!(verify_aggregate_over_hash_accounts_with_coalition_key(
            &registry,
            attestation.signature.clone(),
            &message_hash,
            REGISTRY_VERSION,
            &nodes,
            &key,
        )
        .expect("keyed dispute path must run"));

        let mut bad = key;
        bad.y[0] ^= 0x01;
        assert_eq!(
            verify_aggregate_over_hash_accounts_with_coalition_key(
                &registry,
                attestation.signature,
                &message_hash,
                REGISTRY_VERSION,
                &nodes,
                &bad,
            )
            .unwrap_err(),
            AccountError::Attestation(AttestationError::InvalidCoalitionKey)
        );
    }

    #[test]
    fn verify_attestation_accounts_rejects_version_mismatch() {
        let mut accounts = Accounts::with_version(REGISTRY_VERSION + 1);
        let (registry, nodes) = accounts.split();
        assert_eq!(
            verify_attestation(&fixture_attestation(), &registry, &nodes).unwrap_err(),
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
            verify_attestation(&fixture_attestation(), &registry, &nodes).unwrap_err(),
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
            verify_attestation(&fixture_attestation(), &registry, &nodes).unwrap_err(),
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
            verify_attestation(&fixture_attestation(), &registry, &nodes).unwrap_err(),
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
            verify_attestation(&attestation, &registry, &nodes).unwrap_err(),
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
            verify_attestation(&fixture_attestation(), &registry, &nodes).unwrap_err(),
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
            verify_attestation(&fixture_attestation(), &registry, &nodes).unwrap_err(),
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

    #[cfg(feature = "anchor")]
    #[test]
    fn account_errors_preserve_their_codes_in_anchor_errors() {
        let errors = [
            AccountError::Attestation(AttestationError::InvalidSignature),
            AccountError::AccountBorrowFailed,
            AccountError::InvalidAccountOwner,
            AccountError::InvalidRegistryAccount,
            AccountError::InvalidRegistryPda,
            AccountError::InvalidNodeAccount,
            AccountError::InvalidNodePda,
        ];

        for error in errors {
            let expected = ProgramError::Custom(error.code());
            let anchor_error = anchor_lang::error::Error::from(error);
            match anchor_error {
                anchor_lang::error::Error::ProgramError(program_error) => {
                    assert_eq!(program_error.program_error, expected);
                }
                anchor_lang::error::Error::AnchorError(_) => {
                    panic!("account errors must remain Solana program errors");
                }
            }
        }
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
