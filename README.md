# molpha-verifier
[![crate](https://img.shields.io/crates/v/molpha-verifier?&label=molpha-verifier&color=ffc933)](https://crates.io/crates/molpha-verifier)

Framework-independent Rust verifier for Molpha updates, compatible with Solana program and native Rust consumers.

The downstream Solana program (or any other consumer) owns registry account types and I/O. This crate only takes plain data — no Anchor, Pinocchio, or `AccountInfo` dependency — and verifies the same checks as the EVM `Validator` reference path.

## What it verifies

Given an [`AttestationPayload`](src/payload.rs) (or combined [`Attestation`](src/payload.rs)), a [`SchnorrSignature`](src/payload.rs), and the signing nodes' secp256k1 pubkeys, verification:

1. Rejects an invalid / zero aggregate scalar `s`
2. Enforces `popcount(signers_bitmap) ≥ signatures_required`
3. Re-derives the deterministic selection bitmap and requires `signers ⊆ selection`
4. Reconstructs the coalition key `Σ X_i` from ordered signer pubkeys
5. Hashes the EVM-compatible message (`MOLPHA_MESSAGE_V1` domain) over `source_id`, registry version, threshold, signers bitmap, raw `value` bytes, and canonical timestamp
6. Recovers the commitment address via the Schnorr→ECDSA trick and matches `commitment_addr`

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
| `commitment_addr` | `[u8; 20]` | Ethereum address of nonce point `R` |
| `signers_bitmap` | `[u8; 32]` | EVM `uint256` bitmap (big-endian) |

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
```

## Usage

### Already-resolved signers

```rust
use molpha_verifier::{verify_attestation, Attestation, SignerXy};

// `ordered_signers`: one (x, y) per set bit of `attestation.signature.signers_bitmap`,
// in ascending bit-index order (same order as EVM Validator.verify).
verify_attestation(
    &attestation,
    node_count,
    redundancy_buffer,
    &ordered_signers,
)?;
```

Compressed (33-byte) pubkeys: `verify_attestation_compressed`.

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

Signer resolution alone: `resolve_registry_signers` / `resolve_registry_signers_indexed` (the indexed form also returns bit positions, useful when splitting a union bitmap).

### Dispute path

For instructions that verify an aggregate signature over an arbitrary message hash (slash / dispute semantics):

```rust
use molpha_verifier::verify_aggregate_over_hash;

// Ok(true) = valid, Ok(false) = invalid (slashable), Err = malformed input
let valid = verify_aggregate_over_hash(
    &ordered_signers,
    &signature.agg_sig_s,
    &signature.commitment_addr,
    &message_hash,
)?;
```

Registry-resolved variant: `verify_aggregate_over_hash_resolved` (same snapshot version check; no wall-clock / previous-version grace window).

## Modules

| Module | Role |
| --- | --- |
| `payload` | Plain `AttestationPayload`, `SchnorrSignature`, and `Attestation` structs |
| `verify` | High-level verify, coalition reconstruction, dispute helpers |
| `onchain` | Snapshot signer resolution (`resolve_registry_signers*`) over `RegistryView` / `NodeEntry` |
| `selection` | Deterministic selection bitmap (`MOLPHA_SELECTION_V1`) |
| `message` | EVM-compatible message hash (`MOLPHA_MESSAGE_V1`) |
| `bitmap` | u256 bitmap helpers and group sampling |
| `coalition` | secp256k1 point sum accumulator |
| `scalar` | Schnorr→ECDSA inputs, ETH address from pubkey |
| `state` | Framework-agnostic snapshot view (`RegistryView`, `NodeEntry`, `MAX_REGISTRY_NODES`) |
| `error` | `AttestationError` — map at the program call boundary |

## Features

| Feature | Effect |
| --- | --- |
| *(default)* | Pure verification; no Borsh |
| `borsh` | Derive Borsh on `AttestationPayload`, `SchnorrSignature`, and `Attestation` |
| `thiserror` | `Display` and `std::error::Error` on [`AttestationError`](src/error.rs) for off-chain tooling |

## Development

```bash
cargo test
cargo test --all-features
cargo clippy --all-targets --all-features -- -D warnings
cargo fmt --all -- --check

# End-to-end example (Borsh decode + compressed-pubkey verify)
cargo run --example verify_attestation --features borsh,fixtures
```

## License

MIT — see [LICENSE](LICENSE).
