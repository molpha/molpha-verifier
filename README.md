# molpha-verifier
[![crate](https://img.shields.io/crates/v/molpha-verifier?&label=molpha-verifier&color=ffc933)](https://crates.io/crates/molpha-verifier)

Framework-independent Rust verifier for Molpha updates, compatible with Solana program and native Rust consumers.

The downstream Solana program (or any other consumer) owns registry account types and I/O. By default this crate only takes plain data — no Anchor, Pinocchio, or `AccountInfo` dependency.

If you *are* on Solana and would rather not write the account plumbing, the opt-in [`solana` feature](#account-path-solana-feature) takes the program's `Registry` and `Node` accounts as `&AccountInfo` and does it for you.

## What it verifies

Given an [`AttestationPayload`](src/payload.rs) (or combined [`Attestation`](src/payload.rs)), a [`SchnorrSignature`](src/payload.rs), and the signing nodes' secp256k1 pubkeys, verification:

1. Rejects an invalid / zero aggregate scalar `s`
2. Enforces `popcount(signers_bitmap) ≥ signatures_required`
3. Requires the supplied signer set to be exactly `popcount(signers_bitmap)` long
4. Re-derives the deterministic selection bitmap and requires `signers ⊆ selection`
5. Reconstructs the coalition key `Σ X_i` from ordered signer pubkeys, normalizing it with a field inversion or [checking a supplied affine key](#supplying-the-coalition-key)
6. Hashes the message (`MOLPHA_MESSAGE_V1` domain) over `source_id`, registry version, threshold, signers bitmap, raw `value` bytes, and canonical timestamp
7. Recovers the commitment address via the Schnorr→ECDSA trick and matches `commitment`

Checks run cheapest-first, so a malformed attestation is rejected before it costs a selection derivation or a curve operation.

Optional helpers resolve ordered signers from a plain [`RegistryView`](src/state.rs) + [`NodeEntry`](src/state.rs) slice against an immutable, version-addressed registry snapshot (`nodes[bit]`). Node status is ignored: a node deactivated in a later version remains valid evidence for that historical snapshot.

### `AttestationPayload`

Content fields carried with the attestation:

| Field | Type | Notes |
| --- | --- | --- |
| `value` | `[u8; 32]` | Attested value; hashed as-is into the message |
| `source_id` | `[u8; 32]` | Source identifier (often ASCII-padded) |
| `registry_version` | `u32` | Registry snapshot referenced by the attestation |
| `signatures_required` | `u8` | Threshold encoded in the payload |
| `canonical_timestamp` | `u64` | Round timestamp; used in selection seed |

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

Immutable, version-addressed snapshot view (borrowed `nodes` so on-chain callers can pass `&registry.nodes` without copying):

| Field | Type | Notes |
| --- | --- | --- |
| `version` | `u32` | Must match `attestation.payload.registry_version` |
| `node_count` | `u16` | Populated length of `nodes` |
| `redundancy_buffer` | `u8` | Passed through to selection / threshold checks |
| `nodes` | `&[[u8; 32]]` | Ordered node account pubkeys; only `nodes[..node_count]` is used |

### `NodeEntry`

One already owner-checked signer account + secp256k1 coordinates. `account` must equal `registry.nodes[bit]` for the corresponding set bit:

| Field | Type | Notes |
| --- | --- | --- |
| `account` | `[u8; 32]` | Node account pubkey |
| `x` / `y` | `[u8; 32]` | Affine secp256k1 coordinates (big-endian) |

Cap: `MAX_REGISTRY_NODES` (256).

## Install

```toml
[dependencies]
molpha-verifier = "0.3"

# With Borsh support for wire-format decode/encode:
# molpha-verifier = { version = "0.3", features = ["borsh"] }

# On Solana, to pass accounts instead of plain data:
# molpha-verifier = { version = "0.3", features = ["solana"] }

# In an Anchor 1.2 program, with instruction-type and error integration:
# molpha-verifier = { version = "0.3", features = ["anchor"] }
```

## Usage

### Already-resolved signers

```rust
use molpha_verifier::{verify, Attestation, RegistryView, SignerXy};

// `ordered_signers`: one (x, y) per set bit of `attestation.signature.signers_bitmap`,
// in ascending bit-index order.
let registry = RegistryView {
    version: attestation.payload.registry_version,
    node_count,
    redundancy_buffer,
    nodes: &[],
};
verify(&attestation, &ordered_signers, &registry)?;
```

### Registry-resolved path

```rust
use molpha_verifier::{
    verify_attestation_resolved, NodeEntry, RegistryView,
};

// `registry` is an immutable version-addressed snapshot.
// `entries` must be one NodeEntry per set bit of signers_bitmap, in ascending bit order;
// each entry.account must equal registry.nodes[bit].
verify_attestation_resolved(&attestation, &registry, &entries)?;
```

Requires `attestation.payload.registry_version == registry.version`. The caller must owner-check and deserialize accounts; this crate binds each set bit to `registry.nodes[bit]` and runs crypto.

Signer resolution alone: `resolve_signers`. For two overlapping bitmaps, `resolve_intersected_signers` walks the union once.

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

### Account path (`solana` feature)

With the `solana` feature the crate reads the accounts itself — hand it the `Registry` account and the signers' `Node` accounts and it does the rest:

```rust
use molpha_verifier::solana::verify_attestation;

// `node_accounts` are the signers' Node accounts in ascending signers_bitmap bit order.
verify_attestation(
    &attestation,
    &registry_account,       // &AccountInfo
    ctx.remaining_accounts,  // &[AccountInfo]
)?;
```

Anchor accounts are an 8-byte discriminator plus Borsh (or, for `zero_copy`, `repr(C)`), so no `anchor-lang` dependency is needed to read them: Anchor consumers pass `to_account_info()`, native programs pass their `AccountInfo`s directly.

Every account is checked before any field is trusted:

| Check | Registry | Node |
| --- | --- | --- |
| Owner is Molpha `PROGRAM_ID` | ✓ | ✓ |
| Anchor discriminator | `sha256("account:Registry")[..8]` | `sha256("account:Node")[..8]` |
| Minimum length | `REGISTRY_ACCOUNT_LEN` (8,208) | `NODE_ACCOUNT_LEN` (152) |
| Body decode | fixed offsets (`zero_copy`) | fixed offsets (pubkey `x` / `y`) |

The PDA check is load-bearing rather than ceremony: the program also creates `Registry`-shaped accounts under other seed prefixes, and re-seeding from the account's *own* version / owner means a snapshot cannot be relabelled or a node identity transplanted in place. Node **status is deliberately ignored** — a node deactivated in a later version remains valid evidence for a historical snapshot.

Errors come back as [`solana::AccountError`](src/solana.rs), which wraps `AttestationError` so one `?` covers both account I/O and crypto. `From<AccountError> for ProgramError` maps to `ProgramError::Custom(ERROR_CODE_BASE + n)`, based at `0x4D4F_0000` — outside Anchor's reserved *and* `6000+` user ranges, so it never collides with a consumer's own codes.

### Anchor integration (`anchor` feature)

The `anchor` feature includes the `solana` adapters and makes `AttestationPayload`,
`SchnorrSignature`, `Attestation`, and `CoalitionKey` directly usable as Anchor instruction types. It also
converts `AccountError` into Anchor's error type while preserving the verifier's stable custom
program-error codes:

```rust
use anchor_lang::prelude::*;
use molpha_verifier::{solana::verify_attestation, Attestation};

pub fn submit(ctx: Context<Submit>, attestation: Attestation) -> Result<()> {
    verify_attestation(
        &attestation,
        ctx.accounts.registry.as_ref(),
        ctx.remaining_accounts,
    )?;
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
| `RegistryAccount::load` | Borrowed registry account; `view()` exposes a zero-copy `RegistryView` tied to the borrow |
| `NodeEntry::load` | Validate and decode one `Node` account (pubkey coordinates + account key) |
| `resolve_signers_accounts` | Registry + signer `Node` accounts → ordered `(x, y)` pubkeys |

### Dispute path

For instructions that verify an aggregate signature over an arbitrary message hash (slash / dispute semantics):

```rust
use molpha_verifier::verify_aggregate_over_hash;

// Ok(true) = valid, Ok(false) = invalid (slashable), Err = malformed input
let valid = verify_aggregate_over_hash(
    &signature.agg_sig_s,
    &signature.commitment,
    &message_hash,
    &ordered_signers,
)?;
```

### Supplying the coalition key

Every verification entry point has a `*_with_coalition_key` variant that takes the affine
coalition key `Σ X_i` as a [`CoalitionKey`](src/coalition.rs) `{ x, y }` (big-endian, 64 bytes)
instead of computing it:

| Computes the key | Takes the key |
| --- | --- |
| `verify` | `verify_with_coalition_key` |
| `verify_attestation_resolved` | `verify_attestation_resolved_with_coalition_key` |
| `verify_aggregate_over_hash` | `verify_aggregate_over_hash_with_coalition_key` |
| `verify_aggregate_over_hash_resolved` | `verify_aggregate_over_hash_resolved_with_coalition_key` |
| `solana::verify_attestation` | `solana::verify_attestation_with_coalition_key` |
| `solana::verify_aggregate_over_hash_accounts` | `solana::verify_aggregate_over_hash_accounts_with_coalition_key` |

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
use molpha_verifier::{coalition_key, verify_with_coalition_key};

let key = coalition_key(&ordered_signers)?; // off-chain, or any library's point sum
verify_with_coalition_key(&attestation, &ordered_signers, &registry, &key)?;
```

## Modules

| Module | Role |
| --- | --- |
| `payload` | Plain `AttestationPayload`, `SchnorrSignature`, and `Attestation` structs |
| `pop` | Canonical secp256k1 node-key validation and proof-of-possession verification |
| `verify` | High-level verify, coalition reconstruction, dispute helpers |
| `onchain` | Snapshot signer resolution (`resolve_signers*`) over `RegistryView` / `NodeEntry` |
| `selection` | Deterministic selection bitmap (`MOLPHA_SELECTION_V1`) |
| `message` | Molpha message hash (`MOLPHA_MESSAGE_V1`) |
| `bitmap` | [`Bitmap`] (256-bit set) and deterministic group sampling |
| `coalition` | secp256k1 point sum accumulator and the `CoalitionKey` input |
| `scalar` | Schnorr→ECDSA inputs, ETH address from pubkey |
| `state` | Framework-agnostic snapshot view (`RegistryView`, `NodeEntry`, `MAX_REGISTRY_NODES`) |
| `solana` | *(feature-gated)* `AccountInfo` adapters — owner / discriminator / PDA checks, account decode |
| `error` | `AttestationError` — map at the program call boundary |

## Features

| Feature | Effect |
| --- | --- |
| *(default)* | Pure verification; no Borsh, Solana account, or Anchor dependency |
| `borsh` | Derive Borsh on `AttestationPayload`, `SchnorrSignature`, and `Attestation` |
| `thiserror` | `Display` and `std::error::Error` on [`AttestationError`](src/error.rs) and `NodePopError` for off-chain tooling |
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
