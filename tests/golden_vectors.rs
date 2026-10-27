//! Golden vectors for deterministic selection derivation.
//!
//! Consensus-critical: output must match the EVM reference bit-for-bit. A failure here is a
//! hard-fork-class change, not a casual test update.

use molpha_verifier::bitmap::derive_group_bitmap;
use molpha_verifier::selection::{derive_selection_bitmap, SELECTION_WINDOW_MS};
use molpha_verifier::{NodeEntry, RegistryView};
use sha2::{Digest, Sha256};

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
                hasher.update(got.to_bytes());
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
        // The seed reads the 1 s window index; the sub-window millisecond offset must not matter.
        let window = 1_705_257_421u64.wrapping_add(u64::from(i) * 99_991);
        let timestamp = window
            .wrapping_mul(SELECTION_WINDOW_MS)
            .wrapping_add(u64::from(i * 37) % SELECTION_WINDOW_MS);
        for node_count in [1u32, 2, 3, 7, 12, 31, 32, 33, 64, 100, 128, 200, 255, 256] {
            for signatures_required in [0u8, 1, 5, 17, 64, 200, 255] {
                for redundancy_buffer in [0u8, 2, 9, 128, 255] {
                    let registry = RegistryView {
                        version: registry_version,
                        node_count: node_count as u16,
                        redundancy_buffer,
                        nodes: &[],
                    };
                    let got = derive_selection_bitmap(
                        &source_id,
                        timestamp,
                        signatures_required,
                        &registry,
                    )
                    .expect("valid parameters must derive");
                    hasher.update(got.to_bytes());
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

// ---------------------------------------------------------------------------
// Selection over a registry with holes
// ---------------------------------------------------------------------------

const HOLE_VECTORS: &str = include_str!("fixtures/selection_holes.vectors");

/// `(live hex, source, live, version, timestamp, required, buffer)`.
type HoleCase = (String, [u8; 32], [u8; 32], u32, u64, u8, u8);

/// One line per case: `live source version timestamp_ms required buffer selection`, whitespace
/// separated. `live` and `selection` are 32-byte big-endian bitmaps (bit `i` = slot `i`), `source`
/// is 32 bytes, all hex. The node, gateway and SDK read the same file.
fn hole_cases() -> Vec<HoleCase> {
    let mut cases = Vec::new();
    for i in 0..48u32 {
        let digest = sweep_seed(1_000 + i);
        let slots = [5u32, 9, 12, 33, 64, 100, 130, 256][(i % 8) as usize];
        let mut live = molpha_verifier::Bitmap::EMPTY;
        for slot in 0..slots {
            // About one slot in four is a hole; the last slot is always live.
            let hole = slot + 1 < slots && sweep_seed(i * 1_000 + slot)[0].is_multiple_of(4);
            if !hole {
                live.set_bit(slot as usize);
            }
        }
        let source = sweep_seed(2_000 + i);
        let version = i * 3 + 1;
        let timestamp = (1_705_257_421u64 + u64::from(i) * 4_243) * SELECTION_WINDOW_MS
            + u64::from(digest[1]) * 3;
        let required = [1u8, 3, 5, 18][(i % 4) as usize];
        let buffer = [0u8, 2, 8][(i % 3) as usize];
        cases.push((
            hex(&live.to_bytes()),
            source,
            live.to_bytes(),
            version,
            timestamp,
            required,
            buffer,
        ));
    }
    cases
}

fn view_for<'a>(
    live: &[u8; 32],
    version: u32,
    buffer: u8,
    table: &'a mut Vec<NodeEntry>,
) -> RegistryView<'a> {
    let live = molpha_verifier::Bitmap::load(live);
    let last = (0..256).rev().find(|slot| live.bit_set(*slot)).unwrap();
    *table = (0..=last)
        .map(|slot| NodeEntry {
            account: if live.bit_set(slot) {
                [(slot % 255) as u8 + 1; 32]
            } else {
                [0; 32]
            },
            ..NodeEntry::default()
        })
        .collect();
    RegistryView {
        version,
        node_count: table.len() as u16,
        redundancy_buffer: buffer,
        nodes: table,
    }
}

/// The selection committee over a registry with holes: the dense draw over the live members,
/// mapped to their slots. Regenerate with `MOLPHA_REGEN_VECTORS=1 cargo test --test
/// golden_vectors hole_vectors` only for a deliberate consensus change.
#[test]
fn selection_over_holes_matches_the_shared_vectors() {
    let mut lines = Vec::new();
    for (live_hex, source, live, version, timestamp, required, buffer) in hole_cases() {
        let mut table = Vec::new();
        let registry = view_for(&live, version, buffer, &mut table);
        let got = derive_selection_bitmap(&source, timestamp, required, &registry)
            .expect("valid parameters must derive");
        lines.push(format!(
            "{live_hex} {} {version} {timestamp} {required} {buffer} {}",
            hex(&source),
            hex(&got.to_bytes())
        ));
    }
    let generated = lines.join("\n") + "\n";
    if std::env::var("MOLPHA_REGEN_VECTORS").is_ok() {
        std::fs::write(
            concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/fixtures/selection_holes.vectors"
            ),
            &generated,
        )
        .unwrap();
        return;
    }
    assert_eq!(
        generated, HOLE_VECTORS,
        "selection over holes changed — this is a consensus break, not a test to update"
    );
}

fn hex(bytes: &[u8; 32]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
