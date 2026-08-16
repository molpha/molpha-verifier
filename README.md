# molpha-verifier
[![crate](https://img.shields.io/crates/v/molpha-verifier?&label=molpha-verifier&color=ffc933)](https://crates.io/crates/molpha-verifier)

Framework-independent Rust verifier for Molpha updates, compatible with Solana program and native Rust consumers.

The downstream Solana program (or any other consumer) owns registry account types and I/O. This crate only takes plain data — no Anchor, Pinocchio, or `AccountInfo` dependency — and verifies the same checks as the EVM `Validator` reference path.

## What it verifies

Given a signed [`DataUpdate`](src/payload.rs) and the signing nodes' secp256k1 pubkeys, verification:

1. Rejects an invalid / zero aggregate scalar `s`
2. Enforces `popcount(signers_bitmap) ≥ signatures_required`
3. Re-derives the deterministic selection bitmap and requires `signers ⊆ selection`
4. Reconstructs the coalition key `Σ X_i` from ordered signer pubkeys
5. Hashes the EVM-compatible message (`MOLPHA_MESSAGE_V1` domain) over `source_id`, registry version, threshold, signers bitmap, raw `value` bytes, and canonical timestamp
6. Recovers the commitment address via the Schnorr→ECDSA trick and matches `commitment_addr`

Optional helpers resolve ordered signers from a plain [`RegistryView`](src/state.rs) + [`NodeEntry`](src/state.rs) slice, including previous-version remove-transition remapping.

### `DataUpdate`

Field order matches on-chain `SubmitDataUpdateArgs` for mechanical copying:

| Field | Type | Notes |
| --- | --- | --- |
| `source_id` | `[u8; 32]` | Source identifier (often ASCII-padded) |
| `registry_version` | `u32` | Registry snapshot referenced by the update |
| `value` | `Vec<u8>` | Arbitrary-length payload; hashed as-is into the message |
| `canonical_timestamp` | `i64` | Round timestamp; used in selection seed |
| `signatures_required` | `u8` | Threshold encoded in the payload |
| `agg_sig_s` | `[u8; 32]` | Aggregate Schnorr scalar `s` |
| `commitment_addr` | `[u8; 20]` | Ethereum address of nonce point `R` |
| `signers_bitmap` | `[u8; 32]` | EVM `uint256` bitmap (big-endian) |

With the `borsh` feature, `value` serializes as standard Borsh `Vec<u8>` (u32 LE length prefix + bytes), matching Anchor `Vec<u8>` on-chain.

## Install

```toml
[dependencies]
molpha-verifier = "0.2"

# With Borsh support for wire-format decode/encode:
# molpha-verifier = { version = "0.2", features = ["borsh"] }
```

## Usage

### Already-resolved signers

```rust
use molpha_verifier::{verify_data_update, DataUpdate, SignerXy};

// `ordered_signers`: one (x, y) per set bit of `payload.signers_bitmap`,
// in ascending bit-index order (same order as EVM Validator.verify).
verify_data_update(
    &payload,
    node_count,
    redundancy_buffer,
    &ordered_signers,
)?;
```

Compressed (33-byte) pubkeys: `verify_data_update_compressed`.

### Registry-resolved path

```rust
use molpha_verifier::{
    verify_data_update_resolved, NodeEntry, RegistryView,
};

verify_data_update_resolved(
    &payload,
    &registry,
    redundancy_buffer,
    now,
    &entries,
)?;
```

The caller must owner-check and deserialize accounts; this crate only validates indices / versions and runs crypto.

### Dispute path

For instructions that verify an aggregate signature over an arbitrary message hash (slash / dispute semantics):

```rust
use molpha_verifier::verify_aggregate_over_hash;

// Ok(true) = valid, Ok(false) = invalid (slashable), Err = malformed input
let valid = verify_aggregate_over_hash(
    &ordered_signers,
    &payload.agg_sig_s,
    &payload.commitment_addr,
    &message_hash,
)?;
```

Registry-resolved variant: `verify_aggregate_over_hash_resolved`.

## Modules

| Module | Role |
| --- | --- |
| `payload` | Plain `DataUpdate` struct (field-compatible with on-chain args) |
| `verify` | High-level verify, coalition reconstruction, dispute helpers |
| `onchain` | Signer resolution over `RegistryView` / `NodeEntry` |
| `selection` | Deterministic selection bitmap (`MOLPHA_SELECTION_V1`) |
| `message` | EVM-compatible message hash (`MOLPHA_MESSAGE_V1`) |
| `bitmap` | u256 bitmap helpers and group sampling |
| `coalition` | secp256k1 point sum accumulator |
| `scalar` | Schnorr→ECDSA inputs, ETH address from pubkey |
| `state` | Framework-agnostic registry / node view types |
| `error` | `DataUpdateError` — map at the program call boundary |

## Features

| Feature | Effect |
| --- | --- |
| *(default)* | Pure verification; no Borsh |
| `borsh` | Derive Borsh on `DataUpdate` (length-prefixed `value`) |

## Development

```bash
cargo test
cargo test --all-features
cargo clippy --all-targets --all-features -- -D warnings
cargo fmt --all -- --check

# End-to-end example (Borsh decode + compressed-pubkey verify)
cargo run --example verify_data_update --features borsh
```

See [docs/DOCUMENTATION.md](docs/DOCUMENTATION.md) for the full API reference, error table, and integration guide.

## License

MIT — see [LICENSE](LICENSE).
