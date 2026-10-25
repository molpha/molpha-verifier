# molpha-verifier
[![crate](https://img.shields.io/crates/v/molpha-verifier?&label=molpha-verifier&color=ffc933)](https://crates.io/crates/molpha-verifier)

Framework-independent Rust verifier for Molpha updates, compatible with Solana program and native Rust consumers.

The downstream Solana program (or any other consumer) owns registry account types and I/O. By default this crate only takes plain data — no Anchor, Pinocchio, or `AccountInfo` dependency.

If you *are* on Solana and would rather not write the account plumbing, the opt-in [`solana` feature](#account-path-solana-feature) takes the program's `Registry` account as `&AccountInfo` and does it for you. Each registry member record carries the node's secp256k1 key, so no `Node` accounts are needed.

## What it verifies

Given an [`Attestation`](src/payload.rs) (payload plus [`SchnorrSignature`](src/payload.rs)) and the [`RegistryView`](src/state.rs) of the registry snapshot it names, verification:

1. Requires `attestation.payload.registry_version == registry.version`
2. Rejects an invalid / zero aggregate scalar `s`
3. Enforces `popcount(signers_bitmap) ≥ signatures_required`
4. Re-derives the deterministic selection bitmap and requires `signers ⊆ selection`
5. Reconstructs the coalition key `Σ X_i` from the snapshot's member keys (`registry.nodes[bit]` for each set bit), normalizing it with a field inversion or [checking a supplied affine key](#supplying-the-coalition-key)
6. Hashes the message (`MOLPHA_MESSAGE_V1` domain, 141-byte preimage) over `value`, `source_id`, registry version, threshold, timestamp (unix milliseconds) and the signers bitmap
7. Recovers the commitment address via the Schnorr→ECDSA trick and matches `commitment`

Checks run cheapest-first, so a malformed attestation is rejected before it costs a selection derivation or a curve operation.

Signer keys come only from the immutable, version-addressed snapshot, so the caller supplies no per-signer data. A signing-key rotation publishes a new snapshot with the new key at the same index; an older snapshot keeps the key that signed under it. Node status is not part of the snapshot either: a node deactivated in a later version remains valid evidence for that historical snapshot.

### `AttestationPayload`

Content fields carried with the attestation:

| Field | Type | Notes |
| --- | --- | --- |
| `value` | `[u8; 32]` | Attested value; hashed as-is into the message |
| `source_id` | `[u8; 32]` | Source identifier (often ASCII-padded) |
| `registry_version` | `u32` | Registry snapshot referenced by the attestation |
| `signatures_required` | `u8` | Threshold encoded in the payload |
| `timestamp` | `u64` | Gateway-assigned round time in unix **milliseconds**; selection reads `timestamp / SELECTION_WINDOW_MS` (1000), so sub-second precision never changes the committee. Use `timestamp_secs()` for chain-clock comparisons |

### `Attestation`

Combines [`AttestationPayload`] with [`SchnorrSignature`] for wire-format decode/encode when the `borsh` feature is enabled.

### `SchnorrSignature`

Aggregate signature material, passed separately from the payload:

| Field | Type | Notes |
| --- | --- | --- |
| `agg_sig_s` | `[u8; 32]` | Aggregate Schnorr scalar `s` |
| `commitment` | `[u8; 20]` | Ethereum address of nonce point `R` |
| `signers_bitmap` | `[u8; 32]` | bitmap (big-endian) |

### `RegistryView`

Immutable, version-addressed snapshot view. `nodes` is borrowed, so on-chain callers can view the account's member table in place ([`NodeEntry::slice_from_bytes`](src/state.rs)):

| Field | Type | Notes |
| --- | --- | --- |
| `version` | `u32` | Must match `attestation.payload.registry_version` |
| `node_count` | `u16` | Populated length of `nodes` |
| `redundancy_buffer` | `u8` | Passed through to selection / threshold checks |
| `nodes` | `&[NodeEntry]` | Ordered members; only `nodes[..node_count]` is used. Selection-only callers may pass `&[]` |

### `NodeEntry`

One registry member, `repr(C)` and laid out exactly like the program's 96-byte member record, so account data can be reinterpreted in place. Bit `i` of a signers bitmap is `nodes[i]`:

| Field | Type | Notes |
| --- | --- | --- |
| `account` | `[u8; 32]` | Node account pubkey |
| `x` / `y` | `[u8; 32]` | Affine secp256k1 coordinates (big-endian) |

Cap: `MAX_REGISTRY_NODES` (256), the width of the signers bitmap. A snapshot's table holds as many records as its account has room for, which the Molpha program makes exactly its member count.

## Install

```toml
[dependencies]
molpha-verifier = "0.4"

# With Borsh support for wire-format decode/encode:
# molpha-verifier = { version = "0.4", features = ["borsh"] }

# On Solana, to pass accounts instead of plain data:
# molpha-verifier = { version = "0.4", features = ["solana"] }

# In an Anchor 1.2 program, with instruction-type and error integration:
# molpha-verifier = { version = "0.4", features = ["anchor"] }
```

## Usage

### Registry snapshot

```rust
use molpha_verifier::{verify, Attestation, NodeEntry, RegistryView};

// `members`: the snapshot's member table, one NodeEntry (account + key) per registry index.
let registry = RegistryView {
    version: attestation.payload.registry_version,
    node_count,
    redundancy_buffer,
    nodes: &members,
};
// The coalition key is optional; `None` normalizes with a field inversion.
verify(&attestation, &registry, None)?;
```

The caller must owner-check and deserialize the registry account; this crate binds each set bit to `registry.nodes[bit]` and runs crypto. `resolve_signers(&registry, &bitmap)` returns the keys of a bitmap's signers, for example to compute a coalition key off-chain.

### Node key registration

Registration callers can validate a compressed secp256k1 key and its Schnorr proof of possession
in one pass. A successful result is the canonical affine `(x, y)` pair to store in the node
account:

```rust
use molpha_verifier::validate_key_and_verify_pop;

let (pubkey_x, pubkey_y) = validate_key_and_verify_pop(
    &program_id,
    &node_id,
    &compressed_pubkey,
    &pop_sig_r,
    &pop_sig_s,
)?;
```

`NodePopError::InvalidPublicKey` distinguishes malformed/non-recovery-compatible keys from
`NodePopError::InvalidProof`, allowing programs to preserve their existing instruction errors.

### Signing-key rotation

A node replaces its signing key with a [`KeyRotationProof`](src/pop.rs) carrying two signatures
over one digest, `key_rotation_digest(program_id, node, new_key)` =
`keccak256("MOLPHA_NODE_KEY_ROTATION_V1" ‖ program_id ‖ node ‖ new_key_compressed)`:

- the **current key** signs it in the aggregate format `(s, commitment)`, authorizing the change;
- the **new key** proves possession of its secret, `(r, s)`, over the registration PoP message with
  the digest in place of `node_id`: `keccak256("MOLPHA_NODE_POP_V1" ‖ program_id ‖ digest)`. A
  rotation therefore cannot install a rogue key, and neither a registration PoP nor another node's
  rotation PoP replays.

```rust
use molpha_verifier::{verify_key_rotation, KeyRotationError, KeyRotationProof};

// `old_key`: the (x, y) the node has now. Returns the new key's canonical (x, y).
let new_key = verify_key_rotation(&program_id, &node_address, &old_key, &proof)?;
```

Failures are `KeyRotationError::{InvalidPublicKey, InvalidProof, InvalidAuthorization, KeyUnchanged}`.
This checks the two signatures only: the node authority's own signature, single-use of the new key
and the registry version bump belong to the program. The digest names no registry version, so a
version bump between signing and landing does not invalidate the signatures.

### Account path (`solana` feature)

With the `solana` feature the crate reads the account itself — hand it the `Registry` account and it does the rest. No `Node` accounts are passed or parsed:

```rust
use molpha_verifier::solana::verify_attestation;

verify_attestation(
    &attestation,
    &registry_account,   // &AccountInfo
    Some(&coalition_key), // or None
)?;
```

Anchor accounts are an 8-byte discriminator plus Borsh (or, for `zero_copy`, `repr(C)`), so no `anchor-lang` dependency is needed to read them: Anchor consumers pass `to_account_info()`, native programs pass their `AccountInfo`s directly.

The account is checked before any field is trusted:

| Check | Registry |
| --- | --- |
| Owner is Molpha `PROGRAM_ID` | ✓ |
| Anchor discriminator | `sha256("account:Registry")[..8]` |
| Shape | `REGISTRY_HEADER_LEN` (32) bytes, then a whole number of 96-byte member records, at most `MAX_REGISTRY_NODES`; `node_count` within that capacity |
| Body decode | fixed offsets (`zero_copy`): header fields, then the member table |
| Not retired (`verify_attestation` only) | the version's grace window had not ended by the round's timestamp in seconds: `grace_active_until` is `0` or `> ts` (`RegistryAccount::retired_by`) |

A superseded version keeps verifying rounds for its grace window only, so after a node rotates its key the old key stops verifying new rounds when that window ends; `verify_attestation` fails with `AttestationError::RegistryRetired`. A round dated slightly before the version was created is not refused, because the round's stamp and the chain clock that dates versions can disagree by a few seconds (`RegistryAccount::is_active_at` applies the program's full rule if you want it). The dispute path does not check this: evidence signed under any version stays verifiable here, and how late it may be filed is the program's policy (Molpha's closes one settlement window after the version's grace ends). Freshness of the round itself (`maxAge`) remains the caller's policy.

The member table is the tail of the account and its capacity comes from the account length (`registry_account_len(capacity)`), so a program that grows or shrinks the table needs no verifier release. The Molpha program sizes each snapshot to exactly its members, from 32 bytes for an empty registry to 24,608 for a full one; records past `node_count` are never read. Signer keys are validated as curve points when they are summed. Node **status is not part of the snapshot** — a node deactivated in a later version remains valid evidence for a historical snapshot.

Errors come back as [`solana::AccountError`](src/solana.rs), which wraps `AttestationError` so one `?` covers both account I/O and crypto. `From<AccountError> for ProgramError` maps to `ProgramError::Custom(ERROR_CODE_BASE + n)`, based at `0x4D4F_0000` — outside Anchor's reserved *and* `6000+` user ranges, so it never collides with a consumer's own codes.

### Anchor integration (`anchor` feature)

The `anchor` feature includes the `solana` adapters and makes `AttestationPayload`,
`SchnorrSignature`, `Attestation`, `CoalitionKey`, and `KeyRotationProof` directly usable as Anchor instruction types. It also
converts `AccountError` into Anchor's error type while preserving the verifier's stable custom
program-error codes:

```rust
use anchor_lang::prelude::*;
use molpha_verifier::{solana::verify_attestation, Attestation};

pub fn submit(ctx: Context<Submit>, attestation: Attestation) -> Result<()> {
    verify_attestation(&attestation, ctx.accounts.registry.as_ref(), None)?;
    Ok(())
}
```

To include these types in a consuming program's generated IDL, forward its `idl-build` feature:

```toml
[features]
idl-build = [
    "anchor-lang/idl-build",
    "molpha-verifier/idl-build",
]
```

Consumers that want errors named in their own IDL can continue mapping `AccountError` into their
program's `#[error_code]` enum instead of using the direct conversion.

Composable pieces, when the one-call form is too coarse:

| Item | Role |
| --- | --- |
| `RegistryAccount::load` | Borrowed registry account; `view()` exposes a zero-copy `RegistryView` tied to the borrow, `nodes()` the member table in place |

### Dispute path

For instructions that verify an aggregate signature over an arbitrary message hash (slash / dispute semantics):

```rust
use molpha_verifier::verify_aggregate_over_hash_resolved;

// Ok(true) = valid, Ok(false) = invalid (slashable), Err = malformed input. Signer keys come
// from the registry snapshot the evidence names.
let valid = verify_aggregate_over_hash_resolved(&registry, &signature, &message_hash, None)?;
```

Over keys that are not in a registry snapshot, `verify_aggregate_over_hash` takes the signers' `(x, y)` keys directly. A single node's key is a coalition of one: `verify_aggregate_over_hash_with_coalition_key(.., &[key], &CoalitionKey { x, y })`.

### Supplying the coalition key

Every verification entry point can take the affine coalition key `Σ X_i` as a
[`CoalitionKey`](src/coalition.rs) `{ x, y }` (big-endian, 64 bytes) instead of computing it. The
registry-based entry points (`verify`, `verify_aggregate_over_hash_resolved`,
`solana::verify_attestation`, `solana::verify_aggregate_over_hash_accounts`) take it as an
`Option<&CoalitionKey>`, where `None` computes it. The key-slice entry points have a separate
variant: `verify_aggregate_over_hash` / `verify_aggregate_over_hash_with_coalition_key`.

The verifier still sums the signer keys itself, as a Jacobian point `(X, Y, Z)`. Normalizing that
to affine coordinates needs a field inversion, which dominates the fixed cost on Solana (roughly
138k CU). A supplied key replaces it with `X ≡ x·Z²` and `Y ≡ y·Z³ (mod p)`, plus a check that
both coordinates are canonical. `Z ≠ 0` for any sum that isn't infinity, so exactly one key
passes. A wrong key fails with `AttestationError::InvalidCoalitionKey`, and it can't select a
different key. The dispute variants return that as an `Err`, never as an `Ok(false)` verdict.

The key is a property of the point, not of this crate's arithmetic. Any secp256k1 library gives
the same value as the plain sum of the signers' public keys, in any order. It isn't part of the
signed message or of `Attestation`. Carry it next to the attestation, for example in Solana
instruction data. `coalition_key(&signers)` computes it off-chain.

```rust
use molpha_verifier::{coalition_key, resolve_signers, verify};

// off-chain, or any library's point sum over the signers' keys
let signers = resolve_signers(&registry, &attestation.signature.signers_bitmap)?;
let key = coalition_key(&signers)?;
verify(&attestation, &registry, Some(&key))?;
```

## Migrating from 0.3

0.4 matches a program in which every registry version stores its members' keys, and a node can rotate its key. Accounts in the 0.3 layout fail with `InvalidRegistryAccount`, so upgrade together with the program.

- **No signer accounts.** Signer keys come from the registry version. Drop the `Node` accounts you passed after the registry.
- `solana::verify_attestation(att, registry, Option<&CoalitionKey>)` replaces `verify_attestation` and `verify_attestation_with_coalition_key`, and now refuses a version retired before the round (see above).
- `solana::verify_aggregate_over_hash_accounts(registry, &signature, hash, version, Option<&CoalitionKey>)` replaces both dispute adapters.
- `verify(att, &registry, Option<&CoalitionKey>)` resolves signers from the view; `verify_with_coalition_key` is gone.
- `resolve_signers(&registry, bitmap)` and `verify_aggregate_over_hash_resolved(registry, sig, hash, Option<&CoalitionKey>)` take no `NodeEntry` slice.
- `RegistryView.nodes` is `&[NodeEntry]`, and `NodeEntry` is one member record `(node, x, y)`.
- Removed:
  - `resolve_intersected_signers`, `IntersectedResolution` and `verify_attestation_resolved*`
  - `solana::resolve_signers_accounts` and `resolve_intersected_signers_accounts`
  - `NodeEntry::load` and the `NODE_*` constants
  - `REGISTRY_ACCOUNT_LEN`: use `registry_account_len(capacity)` and `REGISTRY_HEADER_LEN`
- Errors:
  - removed: `AttestationError::{SignerCountMismatch, MissingSignerAccount}` and `AccountError::{InvalidNodeAccount, InvalidNodePda}`
  - added: `AttestationError::RegistryRetired`
  - `AccountError` codes 0–4 are unchanged.
- New: key rotation proofs (`verify_key_rotation`, `key_rotation_digest`, `KeyRotationProof`).

## Modules

| Module | Role |
| --- | --- |
| `payload` | Plain `AttestationPayload`, `SchnorrSignature`, and `Attestation` structs |
| `pop` | Canonical secp256k1 node-key validation, proof-of-possession and signing-key rotation verification |
| `verify` | High-level verify, coalition reconstruction, dispute helpers |
| `onchain` | Snapshot signer resolution (`resolve_signers`) and registry-keyed dispute verification |
| `selection` | Deterministic selection bitmap (`MOLPHA_SELECTION_V1`, 1 s window index) |
| `message` | Molpha message hash (`MOLPHA_MESSAGE_V1`) |
| `bitmap` | [`Bitmap`] (256-bit set) and deterministic group sampling |
| `coalition` | secp256k1 point sum accumulator and the `CoalitionKey` input |
| `scalar` | Schnorr→ECDSA inputs, ETH address from pubkey |
| `state` | Framework-agnostic snapshot view (`RegistryView`, `NodeEntry`, `MAX_REGISTRY_NODES`) |
| `solana` | *(feature-gated)* `AccountInfo` adapter — owner / discriminator / shape checks, registry decode |
| `error` | `AttestationError` — map at the program call boundary |

## Features

| Feature | Effect |
| --- | --- |
| *(default)* | Pure verification; no Borsh, Solana account, or Anchor dependency |
| `borsh` | Derive Borsh on `AttestationPayload`, `SchnorrSignature`, `Attestation`, and `KeyRotationProof` |
| `thiserror` | `Display` and `std::error::Error` on [`AttestationError`](src/error.rs), `NodePopError`, and `KeyRotationError` for off-chain tooling |
| `solana` | The [`solana` module](src/solana.rs): verify straight from `&AccountInfo`. Adds modular `solana-account-info`, `solana-program-error`, and `solana-pubkey`; implies `borsh` |
| `anchor` | Anchor 1.2 serialization and error integration; implies `solana` |
| `idl-build` | Adds verifier attestation types to consuming Anchor IDLs; implies `anchor` |

## Development

```bash
cargo test
cargo test --features solana
cargo test --features anchor
cargo test --all-features
cargo clippy --all-targets --all-features -- -D warnings
cargo fmt --all -- --check

# End-to-end example (Borsh decode + verify)
cargo run --example verify_attestation --features borsh,fixtures
```

## License

MIT — see [LICENSE](LICENSE).
