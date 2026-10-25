//! Solana account adapters — verify from the `Registry` account alone.
//!
//! Opt-in (`solana` feature): validates the Molpha `Registry` account and calls
//! [`crate::verify()`]. Reads the Anchor zero-copy layout (8-byte discriminator + body) without
//! depending on `anchor-lang`. Each registry member record carries the node's secp256k1 key, so
//! no `Node` accounts are passed or parsed.
//!
//! # Checks
//!
//! Before trusting account data:
//! 1. **Owner** — `account.owner == program_id`
//! 2. **Discriminator** — matches [`REGISTRY_DISCRIMINATOR`]
//! 3. **Shape** — a [`REGISTRY_HEADER_LEN`] header, then a whole number of
//!    [`REGISTRY_MEMBER_LEN`]-byte member records, at most [`MAX_REGISTRY_NODES`] of them, and
//!    `node_count` within that capacity
//!
//! [`verify_attestation`] also checks that the version was **not retired** by the round's
//! timestamp, in seconds ([`RegistryAccount::retired_by`]). A superseded version keeps verifying
//! rounds for its grace window only, so once a node rotates its key, the old key stops verifying
//! fresh rounds when that window ends. The dispute path ([`verify_aggregate_over_hash_accounts`])
//! does not check it: evidence signed under any version stays verifiable.
//!
//! Signer keys are validated as curve points when they are summed. Node status is not part of
//! the snapshot; historical snapshots may still name deactivated nodes. A key rotation replaces
//! a member's key in the next version only, so a snapshot keeps the key that signed under it.
//!
//! The member table is the tail of the account and its capacity is read from the account length,
//! so a program that grows or shrinks the table needs no verifier release. Header fields are
//! read at fixed offsets pinned to the program layout; discriminator and shape checks fail
//! closed on rename or truncation.
//!
//! # Usage
//! ```ignore
//! use molpha_verifier::solana::verify_attestation;
//!
//! // `coalition_key`: optional affine sum of the signers' keys (cheaper verification).
//! verify_attestation(&attestation, &registry_account, Some(&coalition_key))?;
//! ```

use core::cell::Ref;

use solana_account_info::AccountInfo;
use solana_program_error::ProgramError;
use solana_pubkey::Pubkey;

use crate::{
    onchain::verify_aggregate_over_hash_resolved, state::MAX_REGISTRY_NODES, verify::verify,
    Attestation, AttestationError, CoalitionKey, NodeEntry, RegistryView, SchnorrSignature,
};

/// Registry PDA seeds: `[REGISTRY_SEED_PREFIX, version.to_le_bytes(), [bump]]`.
pub const REGISTRY_SEED_PREFIX: &[u8] = b"molpha_registry";

/// Anchor discriminator for `Registry` (`sha256("account:Registry")[..8]`).
pub const REGISTRY_DISCRIMINATOR: [u8; 8] = [47, 174, 110, 246, 184, 182, 252, 218];

/// Anchor account discriminator length.
pub const DISCRIMINATOR_LEN: usize = 8;

/// Bytes before the member table: the discriminator and the 24-byte header.
pub const REGISTRY_HEADER_LEN: usize = 32;

/// Byte length of one registry member record (a [`NodeEntry`]): account pubkey, then
/// secp256k1 `x` and `y`.
pub const REGISTRY_MEMBER_LEN: usize = NodeEntry::LEN;

/// Serialized `Registry` account length, including the discriminator, for a member table of
/// `capacity` records.
pub const fn registry_account_len(capacity: usize) -> usize {
    REGISTRY_HEADER_LEN + capacity * REGISTRY_MEMBER_LEN
}

// Registry is zero_copy / repr(C). After the 8-byte discriminator:
// grace_active_until(i64), active_from(i64), version(u32), node_count(u16),
// redundancy_buffer(u8), bump(u8), then members[capacity].
const REGISTRY_GRACE_ACTIVE_UNTIL_OFFSET: usize = DISCRIMINATOR_LEN;
const REGISTRY_ACTIVE_FROM_OFFSET: usize = REGISTRY_GRACE_ACTIVE_UNTIL_OFFSET + 8;
const REGISTRY_VERSION_OFFSET: usize = REGISTRY_ACTIVE_FROM_OFFSET + 8;
const REGISTRY_NODE_COUNT_OFFSET: usize = REGISTRY_VERSION_OFFSET + 4;
const REGISTRY_REDUNDANCY_BUFFER_OFFSET: usize = REGISTRY_NODE_COUNT_OFFSET + 2;
const REGISTRY_BUMP_OFFSET: usize = REGISTRY_REDUNDANCY_BUFFER_OFFSET + 1;

/// Offset of the first member record.
pub const REGISTRY_NODES_OFFSET: usize = REGISTRY_BUMP_OFFSET + 1;

const _: () = assert!(REGISTRY_NODES_OFFSET == REGISTRY_HEADER_LEN);

pub const PROGRAM_ID: Pubkey =
    Pubkey::from_str_const("chivcFQgxzwkpLvW41PV431HQ4dYpaW3povQH3AdpQt");

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
    /// Registry discriminator or shape mismatch.
    #[cfg_attr(
        feature = "thiserror",
        error("registry account discriminator or shape mismatch")
    )]
    InvalidRegistryAccount,
    /// Registry is not the canonical PDA for its version.
    #[cfg_attr(
        feature = "thiserror",
        error("registry account is not the canonical PDA for its version")
    )]
    InvalidRegistryPda,
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

/// Validated, borrowed `Registry` account (holds the data borrow for the zero-copy member table).
pub struct RegistryAccount<'a> {
    key: Pubkey,
    data: Ref<'a, [u8]>,
}

impl<'a> RegistryAccount<'a> {
    /// Borrow and validate a `Registry` account (owner / discriminator / shape).
    pub fn load(account: &'a AccountInfo<'_>) -> Result<Self, AccountError> {
        if *account.owner != PROGRAM_ID {
            return Err(AccountError::InvalidAccountOwner);
        }
        let data = account
            .try_borrow_data()
            .map_err(|_| AccountError::AccountBorrowFailed)?;
        let data = Ref::map(data, |bytes| &**bytes);

        if data.len() < REGISTRY_HEADER_LEN || data[..DISCRIMINATOR_LEN] != REGISTRY_DISCRIMINATOR {
            return Err(AccountError::InvalidRegistryAccount);
        }
        let table_len = data.len() - REGISTRY_NODES_OFFSET;
        let capacity = table_len / REGISTRY_MEMBER_LEN;
        let node_count = u16::from_le_bytes(
            data[REGISTRY_NODE_COUNT_OFFSET..REGISTRY_NODE_COUNT_OFFSET + 2]
                .try_into()
                .expect("length checked above"),
        );
        if !table_len.is_multiple_of(REGISTRY_MEMBER_LEN)
            || capacity > MAX_REGISTRY_NODES
            || usize::from(node_count) > capacity
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

    /// Unix seconds this version stops being active at, set when the next version is published;
    /// `0` while it is the current one.
    pub fn grace_active_until(&self) -> i64 {
        i64::from_le_bytes(
            self.data[REGISTRY_GRACE_ACTIVE_UNTIL_OFFSET..REGISTRY_GRACE_ACTIVE_UNTIL_OFFSET + 8]
                .try_into()
                .expect("length checked in load"),
        )
    }

    /// Unix seconds this version was created at. It is not active before.
    pub fn active_from(&self) -> i64 {
        i64::from_le_bytes(
            self.data[REGISTRY_ACTIVE_FROM_OFFSET..REGISTRY_ACTIVE_FROM_OFFSET + 8]
                .try_into()
                .expect("length checked in load"),
        )
    }

    /// Whether the version's grace window had ended by `unix_secs`. The current version is never
    /// retired.
    pub fn retired_by(&self, unix_secs: i64) -> bool {
        let grace_active_until = self.grace_active_until();
        grace_active_until != 0 && grace_active_until <= unix_secs
    }

    /// Whether the version was active at `unix_secs`: created by then and not retired. This is
    /// the program's rule for the time it checks a version at.
    pub fn is_active_at(&self, unix_secs: i64) -> bool {
        self.active_from() <= unix_secs && !self.retired_by(unix_secs)
    }

    pub fn bytes(&self) -> &[u8] {
        &self.data
    }

    /// Full ordered member table, viewed in place; only `[..node_count()]` is populated.
    pub fn nodes(&self) -> &[NodeEntry] {
        NodeEntry::slice_from_bytes(&self.data[REGISTRY_NODES_OFFSET..])
            .expect("member table is a whole number of records, checked in load")
    }

    /// Account address of member `index`.
    pub fn node_key(&self, index: usize) -> Result<Pubkey, AccountError> {
        if index >= usize::from(self.node_count()) {
            return Err(AttestationError::InvalidNodeIndex.into());
        }
        Ok(Pubkey::new_from_array(self.nodes()[index].account))
    }

    /// Framework-agnostic view for selection and verification.
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

/// Verify an attestation from its `Registry` account.
///
/// The version must not have been retired by the round's timestamp
/// ([`RegistryAccount::retired_by`]), so a superseded version stops verifying new rounds when its
/// grace window ends. A round dated slightly before the version was created is not refused: the
/// round's stamp and the chain clock that dates versions may disagree by a few seconds.
/// Freshness of the round itself is the caller's policy.
///
/// `coalition_key` is optional and untrusted; see [`crate::verify()`].
pub fn verify_attestation(
    attestation: &Attestation,
    registry_account: &AccountInfo<'_>,
    coalition_key: Option<&CoalitionKey>,
) -> Result<(), AccountError> {
    let registry = RegistryAccount::load(registry_account)?;
    if attestation.payload.registry_version != registry.version() {
        return Err(AttestationError::InvalidRegistryVersion.into());
    }
    let round_secs = i64::try_from(attestation.payload.timestamp_secs()).unwrap_or(i64::MAX);
    if registry.retired_by(round_secs) {
        return Err(AttestationError::RegistryRetired.into());
    }
    Ok(verify(attestation, &registry.view(), coalition_key)?)
}

/// Verify an aggregate over an arbitrary message hash from the `Registry` account (dispute /
/// slash).
///
/// `Ok(true)` = valid, `Ok(false)` = invalid (slashable), `Err` = malformed account or input. A
/// wrong `coalition_key` is an `Err`, not an `Ok(false)` verdict.
pub fn verify_aggregate_over_hash_accounts(
    registry_account: &AccountInfo<'_>,
    signature: &SchnorrSignature,
    message_hash: &[u8; 32],
    registry_version: u32,
    coalition_key: Option<&CoalitionKey>,
) -> Result<bool, AccountError> {
    let registry = RegistryAccount::load(registry_account)?;
    let view = registry.view();
    if view.version != registry_version {
        return Err(AccountError::InvalidRegistryAccount);
    }
    Ok(verify_aggregate_over_hash_resolved(
        &view,
        signature,
        message_hash,
        coalition_key,
    )?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bitmap::{for_each_set_bit, Bitmap};
    use crate::fixtures::{
        COMMITMENT, PUBKEYS, REDUNDANCY_BUFFER, REGISTERED_NODE_COUNT, REGISTRY_VERSION, S,
        SIGNATURES_REQUIRED, SIGNERS_BITMAP, SOURCE_ID, TIMESTAMP, VALUE,
    };
    use crate::payload::AttestationPayload;

    /// The program sizes a snapshot to its members: the table holds exactly `node_count`.
    const EXACT_FIT: usize = REGISTERED_NODE_COUNT as usize;
    /// A table with room to spare, which the verifier reads the same way.
    const SPARE_CAPACITY: usize = 96;

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

    fn registry_account_data(version: u32, capacity: usize) -> Vec<u8> {
        let (_, bump) = registry_pda(version);
        let mut data = vec![0u8; registry_account_len(capacity)];
        data[..DISCRIMINATOR_LEN].copy_from_slice(&REGISTRY_DISCRIMINATOR);
        data[REGISTRY_VERSION_OFFSET..REGISTRY_VERSION_OFFSET + 4]
            .copy_from_slice(&version.to_le_bytes());
        data[REGISTRY_NODE_COUNT_OFFSET..REGISTRY_NODE_COUNT_OFFSET + 2]
            .copy_from_slice(&(REGISTERED_NODE_COUNT as u16).to_le_bytes());
        data[REGISTRY_REDUNDANCY_BUFFER_OFFSET] = REDUNDANCY_BUFFER;
        data[REGISTRY_BUMP_OFFSET] = bump;
        for (index, (x, y)) in PUBKEYS.iter().enumerate().take(capacity) {
            let offset = REGISTRY_NODES_OFFSET + index * REGISTRY_MEMBER_LEN;
            data[offset..offset + 32].copy_from_slice(&node_account(index));
            data[offset + 32..offset + 64].copy_from_slice(x);
            data[offset + 64..offset + 96].copy_from_slice(y);
        }
        data
    }

    fn fixture_attestation() -> Attestation {
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

    fn fixture_coalition_key() -> CoalitionKey {
        let mut signers = Vec::new();
        for_each_set_bit(Bitmap::load(&SIGNERS_BITMAP), |bit| {
            signers.push(PUBKEYS[bit]);
            Ok::<(), AttestationError>(())
        })
        .unwrap();
        crate::coalition_key(&signers).unwrap()
    }

    /// Owned buffers behind the registry `AccountInfo`.
    struct Accounts {
        registry_key: Pubkey,
        registry_data: Vec<u8>,
        registry_lamports: u64,
        owner: Pubkey,
    }

    impl Accounts {
        fn new() -> Self {
            Self::with_capacity(EXACT_FIT)
        }

        fn with_capacity(capacity: usize) -> Self {
            Self::with_version_and_capacity(REGISTRY_VERSION, capacity)
        }

        fn with_version(version: u32) -> Self {
            Self::with_version_and_capacity(version, EXACT_FIT)
        }

        fn with_version_and_capacity(version: u32, capacity: usize) -> Self {
            Self {
                registry_key: registry_pda(version).0,
                registry_data: registry_account_data(version, capacity),
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
    fn discriminator_matches_anchor_derivation() {
        // Anchor: sha256("account:<Name>")[..8]
        use sha2::{Digest, Sha256};
        let registry: [u8; 8] = Sha256::digest(b"account:Registry")[..8].try_into().unwrap();
        assert_eq!(registry, REGISTRY_DISCRIMINATOR);
    }

    #[test]
    fn layout_constants_match_the_program_registry() {
        // 8 discriminator + grace(8) + active_from(8) + version(4) + node_count(2) + buffer(1)
        // + bump(1), then 96-byte records.
        assert_eq!(REGISTRY_NODES_OFFSET, 32);
        assert_eq!(REGISTRY_MEMBER_LEN, 96);
        assert_eq!(registry_account_len(0), 32);
        assert_eq!(registry_account_len(1), 128);
        assert_eq!(registry_account_len(106), 10_208);
        assert_eq!(registry_account_len(MAX_REGISTRY_NODES), 24_608);
    }

    #[test]
    fn member_table_matches_raw_account_bytes() {
        let mut accounts = Accounts::with_capacity(SPARE_CAPACITY);
        let info = accounts.registry();
        let registry = RegistryAccount::load(&info).expect("load registry");
        let view = registry.view();
        let data = registry.bytes();

        assert_eq!(view.version, REGISTRY_VERSION);
        assert_eq!(view.node_count, REGISTERED_NODE_COUNT as u16);
        assert_eq!(view.redundancy_buffer, REDUNDANCY_BUFFER);
        assert_eq!(view.nodes.len(), SPARE_CAPACITY);
        for (index, node) in view.nodes.iter().enumerate() {
            let offset = REGISTRY_NODES_OFFSET + index * REGISTRY_MEMBER_LEN;
            assert_eq!(node.account[..], data[offset..offset + 32]);
            assert_eq!(node.x[..], data[offset + 32..offset + 64]);
            assert_eq!(node.y[..], data[offset + 64..offset + 96]);
        }
        for (index, node) in view
            .nodes
            .iter()
            .enumerate()
            .take(REGISTERED_NODE_COUNT as usize)
        {
            assert_eq!(node.account, node_account(index));
            assert_eq!(node.xy(), PUBKEYS[index]);
        }
        assert_eq!(
            view.nodes[REGISTERED_NODE_COUNT as usize],
            NodeEntry::default()
        );
    }

    #[test]
    fn node_key_is_bounded_by_node_count() {
        let mut accounts = Accounts::new();
        let info = accounts.registry();
        let registry = RegistryAccount::load(&info).unwrap();
        assert_eq!(
            registry.node_key(0).unwrap(),
            Pubkey::new_from_array(node_account(0))
        );
        assert_eq!(
            registry
                .node_key(REGISTERED_NODE_COUNT as usize)
                .unwrap_err(),
            AccountError::Attestation(AttestationError::InvalidNodeIndex)
        );
        assert!(registry.node_key(MAX_REGISTRY_NODES).is_err());
    }

    #[test]
    fn registry_account_framing_checks() {
        // Truncated into the header, and into a member record.
        for len in [0, 1, DISCRIMINATOR_LEN, REGISTRY_HEADER_LEN - 1] {
            let mut accounts = Accounts::new();
            accounts.registry_data.truncate(len);
            let info = accounts.registry();
            assert_eq!(
                RegistryAccount::load(&info).unwrap_err(),
                AccountError::InvalidRegistryAccount,
                "length {len} must be rejected"
            );
        }
        let mut accounts = Accounts::new();
        accounts.registry_data.pop();
        let info = accounts.registry();
        assert_eq!(
            RegistryAccount::load(&info).unwrap_err(),
            AccountError::InvalidRegistryAccount
        );

        // Trailing bytes that do not make a whole record.
        let mut accounts = Accounts::new();
        accounts.registry_data.extend_from_slice(&[0xAB; 24]);
        let info = accounts.registry();
        assert_eq!(
            RegistryAccount::load(&info).unwrap_err(),
            AccountError::InvalidRegistryAccount
        );

        let mut accounts = Accounts::new();
        accounts.registry_data[0] ^= 0xff;
        let info = accounts.registry();
        assert_eq!(
            RegistryAccount::load(&info).unwrap_err(),
            AccountError::InvalidRegistryAccount
        );

        let mut accounts = Accounts::new();
        accounts.owner = Pubkey::new_from_array([9u8; 32]);
        let info = accounts.registry();
        assert_eq!(
            RegistryAccount::load(&info).unwrap_err(),
            AccountError::InvalidAccountOwner
        );
    }

    #[test]
    fn registry_capacity_is_bounded_by_the_bitmap_and_by_node_count() {
        // More records than a 256-bit bitmap can address.
        let mut accounts = Accounts::with_capacity(MAX_REGISTRY_NODES + 1);
        let info = accounts.registry();
        assert_eq!(
            RegistryAccount::load(&info).unwrap_err(),
            AccountError::InvalidRegistryAccount
        );

        // `node_count` claims more members than the table holds.
        let mut accounts = Accounts::with_capacity(REGISTERED_NODE_COUNT as usize - 1);
        let info = accounts.registry();
        assert_eq!(
            RegistryAccount::load(&info).unwrap_err(),
            AccountError::InvalidRegistryAccount
        );
    }

    #[test]
    fn verification_does_not_depend_on_table_capacity() {
        for capacity in [EXACT_FIT, SPARE_CAPACITY, MAX_REGISTRY_NODES] {
            let mut accounts = Accounts::with_capacity(capacity);
            let registry = accounts.registry();
            verify_attestation(&fixture_attestation(), &registry, None)
                .unwrap_or_else(|e| panic!("capacity {capacity} must verify: {e:?}"));
        }
    }

    #[test]
    fn verify_attestation_accepts_fixture() {
        let mut accounts = Accounts::new();
        let registry = accounts.registry();
        verify_attestation(&fixture_attestation(), &registry, None)
            .expect("account-path fixture must verify");
    }

    #[test]
    fn verify_attestation_with_coalition_key_accepts_fixture_and_rejects_bad_key() {
        let mut accounts = Accounts::new();
        let registry = accounts.registry();
        let attestation = fixture_attestation();
        let key = fixture_coalition_key();
        verify_attestation(&attestation, &registry, Some(&key))
            .expect("keyed account path must verify");

        let mut bad = key;
        bad.x[0] ^= 0x01;
        assert_eq!(
            verify_attestation(&attestation, &registry, Some(&bad)).unwrap_err(),
            AccountError::Attestation(AttestationError::InvalidCoalitionKey)
        );
    }

    #[test]
    fn verify_attestation_rejects_version_mismatch() {
        let mut accounts = Accounts::with_version(REGISTRY_VERSION + 1);
        let registry = accounts.registry();
        assert_eq!(
            verify_attestation(&fixture_attestation(), &registry, None).unwrap_err(),
            AccountError::Attestation(AttestationError::InvalidRegistryVersion)
        );
    }

    #[test]
    fn verify_attestation_rejects_swapped_registry_keys() {
        let mut accounts = Accounts::new();
        let signers: Vec<usize> = {
            let mut bits = Vec::new();
            for_each_set_bit(Bitmap::load(&SIGNERS_BITMAP), |bit| {
                bits.push(bit);
                Ok::<(), AttestationError>(())
            })
            .unwrap();
            bits
        };
        let non_signer = (0..REGISTERED_NODE_COUNT as usize)
            .find(|bit| !signers.contains(bit))
            .unwrap();
        // Put a non-signer's key in a signer's slot: the sum no longer matches the signature.
        let (a, b) = (
            REGISTRY_NODES_OFFSET + signers[0] * REGISTRY_MEMBER_LEN + 32,
            REGISTRY_NODES_OFFSET + non_signer * REGISTRY_MEMBER_LEN + 32,
        );
        let replacement = accounts.registry_data[b..b + 64].to_vec();
        accounts.registry_data[a..a + 64].copy_from_slice(&replacement);
        let registry = accounts.registry();
        assert_eq!(
            verify_attestation(&fixture_attestation(), &registry, None).unwrap_err(),
            AccountError::Attestation(AttestationError::InvalidAggregateSignature)
        );
    }

    #[test]
    fn verify_attestation_rejects_tampered_value() {
        let mut accounts = Accounts::new();
        let mut attestation = fixture_attestation();
        attestation.payload.value[31] ^= 0x01;
        let registry = accounts.registry();
        assert_eq!(
            verify_attestation(&attestation, &registry, None).unwrap_err(),
            AccountError::Attestation(AttestationError::InvalidAggregateSignature)
        );
    }

    #[test]
    fn verify_aggregate_over_hash_accounts_roundtrip() {
        let mut accounts = Accounts::new();
        let attestation = fixture_attestation();
        let message_hash = attestation.message_hash();
        let registry = accounts.registry();
        let key = fixture_coalition_key();

        for coalition_key in [None, Some(&key)] {
            assert!(verify_aggregate_over_hash_accounts(
                &registry,
                &attestation.signature,
                &message_hash,
                REGISTRY_VERSION,
                coalition_key,
            )
            .expect("dispute path must run"));
        }

        let mut bad = key;
        bad.y[0] ^= 0x01;
        assert_eq!(
            verify_aggregate_over_hash_accounts(
                &registry,
                &attestation.signature,
                &message_hash,
                REGISTRY_VERSION,
                Some(&bad),
            )
            .unwrap_err(),
            AccountError::Attestation(AttestationError::InvalidCoalitionKey)
        );
    }

    #[test]
    fn verify_aggregate_over_hash_accounts_reports_invalid_signature() {
        let mut accounts = Accounts::new();
        let attestation = fixture_attestation();
        let mut message_hash = attestation.message_hash();
        message_hash[0] ^= 0xff;
        let registry = accounts.registry();

        assert!(!verify_aggregate_over_hash_accounts(
            &registry,
            &attestation.signature,
            &message_hash,
            REGISTRY_VERSION,
            None,
        )
        .expect("dispute path must run"));
    }

    #[test]
    fn verify_aggregate_over_hash_accounts_rejects_version_mismatch() {
        let mut accounts = Accounts::new();
        let attestation = fixture_attestation();
        let registry = accounts.registry();
        assert_eq!(
            verify_aggregate_over_hash_accounts(
                &registry,
                &attestation.signature,
                &attestation.message_hash(),
                REGISTRY_VERSION + 1,
                None,
            )
            .unwrap_err(),
            AccountError::InvalidRegistryAccount
        );
    }

    const INVALID_SCALAR: [u8; 32] = [0xFF; 32];

    #[test]
    fn dispute_path_reports_invalid_scalar_as_false() {
        let mut accounts = Accounts::new();
        let attestation = fixture_attestation();
        let message_hash = attestation.message_hash();
        let mut signature = attestation.signature;
        signature.agg_sig_s = INVALID_SCALAR;
        let registry = accounts.registry();
        assert!(!verify_aggregate_over_hash_accounts(
            &registry,
            &signature,
            &message_hash,
            REGISTRY_VERSION,
            None,
        )
        .expect("invalid scalar is a verdict, not an error"));
    }

    /// A bit outside the registry must error even with an invalid scalar (no slashable verdict
    /// on bad input).
    #[test]
    fn dispute_path_errors_on_out_of_range_bit_even_with_invalid_scalar() {
        let mut accounts = Accounts::new();
        let attestation = fixture_attestation();
        let message_hash = attestation.message_hash();
        let mut signature = attestation.signature;
        signature.agg_sig_s = INVALID_SCALAR;
        let mut bitmap = Bitmap::load(&signature.signers_bitmap);
        bitmap.set_bit(REGISTERED_NODE_COUNT as usize);
        signature.signers_bitmap = bitmap.to_bytes();
        let registry = accounts.registry();
        assert_eq!(
            verify_aggregate_over_hash_accounts(
                &registry,
                &signature,
                &message_hash,
                REGISTRY_VERSION,
                None,
            )
            .unwrap_err(),
            AccountError::Attestation(AttestationError::InvalidSignersBitmap)
        );
    }

    fn set_liveness(data: &mut [u8], active_from: i64, grace_active_until: i64) {
        data[REGISTRY_ACTIVE_FROM_OFFSET..REGISTRY_ACTIVE_FROM_OFFSET + 8]
            .copy_from_slice(&active_from.to_le_bytes());
        data[REGISTRY_GRACE_ACTIVE_UNTIL_OFFSET..REGISTRY_GRACE_ACTIVE_UNTIL_OFFSET + 8]
            .copy_from_slice(&grace_active_until.to_le_bytes());
    }

    /// A version verifies a round unless its grace window had ended by the round's timestamp, in
    /// seconds. A round dated before the version's creation is not refused for that.
    #[test]
    fn verify_attestation_refuses_a_version_retired_before_the_round() {
        let round = (TIMESTAMP / 1_000) as i64;
        for (active_from, grace_active_until, verifies, active) in [
            (0, 0, true, true),
            (round, 0, true, true),
            (round + 1, 0, true, false),
            (0, round + 1, true, true),
            (0, round, false, false),
            (0, round - 1, false, false),
        ] {
            let mut accounts = Accounts::new();
            set_liveness(&mut accounts.registry_data, active_from, grace_active_until);
            let info = accounts.registry();
            let registry = RegistryAccount::load(&info).unwrap();
            assert_eq!(
                (registry.active_from(), registry.grace_active_until()),
                (active_from, grace_active_until)
            );
            assert_eq!(registry.retired_by(round), !verifies);
            assert_eq!(registry.is_active_at(round), active);
            drop(registry);
            let result = verify_attestation(&fixture_attestation(), &info, None);
            if verifies {
                result.unwrap_or_else(|e| {
                    panic!("[{active_from}, {grace_active_until}) must verify: {e:?}")
                });
            } else {
                assert_eq!(
                    result.unwrap_err(),
                    AccountError::Attestation(AttestationError::RegistryRetired),
                    "[{active_from}, {grace_active_until})"
                );
            }
        }
    }

    /// Slashing evidence never expires: the dispute path verifies under a version whose grace
    /// window ended long ago.
    #[test]
    fn dispute_path_ignores_liveness() {
        let mut accounts = Accounts::new();
        set_liveness(&mut accounts.registry_data, 0, 1);
        let attestation = fixture_attestation();
        let message_hash = attestation.message_hash();
        let info = accounts.registry();
        assert!(verify_aggregate_over_hash_accounts(
            &info,
            &attestation.signature,
            &message_hash,
            REGISTRY_VERSION,
            None,
        )
        .unwrap());
    }

    /// The 0.3 layout, a fixed 256-address table of 8,208 bytes, is not a whole number of member
    /// records, so it fails closed instead of being misread.
    #[test]
    fn a_registry_in_the_previous_layout_is_rejected() {
        let mut data = vec![0u8; 8_208];
        data[..DISCRIMINATOR_LEN].copy_from_slice(&REGISTRY_DISCRIMINATOR);
        let key = registry_pda(REGISTRY_VERSION).0;
        let mut lamports = 1u64;
        let info = AccountInfo::new(
            &key,
            false,
            false,
            &mut lamports,
            &mut data,
            &PROGRAM_ID,
            false,
        );
        assert_eq!(
            RegistryAccount::load(&info).unwrap_err(),
            AccountError::InvalidRegistryAccount
        );
    }

    /// The genesis version has no members: a bare header.
    #[test]
    fn an_empty_registry_is_a_bare_header() {
        let mut accounts = Accounts::with_capacity(0);
        accounts.registry_data[REGISTRY_NODE_COUNT_OFFSET..REGISTRY_NODE_COUNT_OFFSET + 2]
            .copy_from_slice(&0u16.to_le_bytes());
        assert_eq!(accounts.registry_data.len(), REGISTRY_HEADER_LEN);
        let info = accounts.registry();
        let registry = RegistryAccount::load(&info).unwrap();
        assert!(registry.nodes().is_empty());
        assert_eq!(registry.view().node_count, 0);
        assert!(registry.node_key(0).is_err());
    }

    #[test]
    fn error_codes_are_distinct_and_outside_anchor_ranges() {
        let errors = [
            AccountError::Attestation(AttestationError::InsufficientSigners),
            AccountError::AccountBorrowFailed,
            AccountError::InvalidAccountOwner,
            AccountError::InvalidRegistryAccount,
            AccountError::InvalidRegistryPda,
        ];
        let codes: Vec<u32> = errors.iter().map(AccountError::code).collect();
        let mut sorted = codes.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), codes.len());
        assert!(codes.iter().all(|code| *code > 100_000));

        assert_eq!(
            ProgramError::from(AccountError::InvalidRegistryPda),
            ProgramError::Custom(AccountError::InvalidRegistryPda.code())
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
