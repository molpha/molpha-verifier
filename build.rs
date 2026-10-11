//! Bakes `MOLPHA_PROGRAM_ID` into the crate at compile time (see `solana::PROGRAM_ID`).
//!
//! Release workflows set this from GitHub repository variables; local builds use the
//! default devnet program id below.

const DEFAULT_PROGRAM_ID: &str = "chivcFQgxzwkpLvW41PV431HQ4dYpaW3povQH3AdpQt";

fn main() {
    let program_id = match std::env::var("MOLPHA_PROGRAM_ID") {
        Ok(id) if !id.is_empty() => id,
        _ => DEFAULT_PROGRAM_ID.to_string(),
    };
    println!("cargo:rustc-env=MOLPHA_PROGRAM_ID={program_id}");
}
