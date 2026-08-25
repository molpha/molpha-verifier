//! Byte-exact golden vectors for the deterministic selection derivation.
//!
//! `derive_group_bitmap` / `derive_selection_bitmap` are consensus-critical: their output must
//! match the EVM reference implementation bit for bit, forever. The unit tests in `src/bitmap.rs`
//! pin four hand-checked vectors; this test pins a rolling digest over a wide sweep of
//! `(seed, node_count, group_size)` so any change to the sampling internals — an optimization, a
//! refactor — is caught even where no hand-checked vector exists.
//!
//! If this test fails, the derivation changed. That is a hard-fork-class change, not a test to
//! update casually.

use molpha_verifier::bitmap::derive_group_bitmap;
use molpha_verifier::selection::derive_selection_bitmap;
use sha2::{Digest, Sha256};

/// Deterministic pseudo-random seed for sweep index `i` (no RNG dependency).
fn sweep_seed(i: u32) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"molpha-golden-sweep");
    hasher.update(i.to_be_bytes());
    hasher.finalize().into()
}

#[test]
fn derive_group_bitmap_sweep_digest_is_stable() {
    let mut hasher = Sha256::new();
    let mut count = 0u32;
    for i in 0..24u32 {
        let seed = sweep_seed(i);
        for node_count in 1u32..=64 {
            for group_size in 0u32..=node_count {
                let got = derive_group_bitmap(&seed, node_count, group_size)
                    .expect("valid parameters must derive");
                hasher.update(got);
                count += 1;
            }
        }
    }
    let digest: [u8; 32] = hasher.finalize().into();
    assert_eq!(count, 51_456, "sweep shape changed");
    assert_eq!(
        hex(&digest),
        "133c22a3d4f099d1538057d817c6db4b0351dc08617393bc1a9a5f48b602040a",
        "derive_group_bitmap output changed — this is a consensus break, not a test to update",
    );
}

#[test]
fn derive_selection_bitmap_sweep_digest_is_stable() {
    let mut hasher = Sha256::new();
    for i in 0..64u32 {
        let source_id = sweep_seed(i);
        let registry_version = i.wrapping_mul(7).wrapping_add(1);
        let canonical_timestamp = 1_705_257_421u64.wrapping_add(u64::from(i) * 99_991);
        for node_count in [1u32, 2, 3, 7, 12, 31, 32, 33, 64, 100, 128, 200, 255, 256] {
            for signatures_required in [0u8, 1, 5, 17, 64, 200, 255] {
                for redundancy_buffer in [0u8, 2, 9, 128, 255] {
                    let got = derive_selection_bitmap(
                        &source_id,
                        registry_version,
                        canonical_timestamp,
                        node_count,
                        signatures_required,
                        redundancy_buffer,
                    )
                    .expect("valid parameters must derive");
                    hasher.update(got);
                }
            }
        }
    }
    let digest: [u8; 32] = hasher.finalize().into();
    assert_eq!(
        hex(&digest),
        "f2ae2cd7b44aec35586ca639c9d17c616befd511fa54b54567f3a25afef6fb90",
        "derive_selection_bitmap output changed — this is a consensus break, not a test to update",
    );
}

fn hex(bytes: &[u8; 32]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
