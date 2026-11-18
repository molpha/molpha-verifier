//! The derived source ID an INCONCLUSIVE result is signed under.
//!
//! A source with a policy (node-client `docs/policy.md`) signs its result under its source ID `S`, and,
//! when the policy opts in, an INCONCLUSIVE result (a reason code as the value) under
//! `I(S) = keccak256("MOLPHA_INCONCLUSIVE_V1" || S)`. `verify` is unchanged: a consumer compares the
//! attestation's `source_id` with `S` and `I(S)` after verifying it. Anything else is not its source.

use solana_keccak_hasher::hashv;

use crate::payload::AttestationPayload;

/// The raw ASCII domain tag of `I(S)`; the 32 bytes of `S` follow it.
pub const INCONCLUSIVE_TAG: &[u8] = b"MOLPHA_INCONCLUSIVE_V1";

/// `I(S) = keccak256("MOLPHA_INCONCLUSIVE_V1" || S)`: 22 tag bytes, then `S`. A source preimage starts
/// with `{`, so `I(S)` is never a source's own ID.
pub fn inconclusive_id(source_id: &[u8; 32]) -> [u8; 32] {
    hashv(&[INCONCLUSIVE_TAG, source_id]).to_bytes()
}

/// What a verified attestation says about source `S`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// Signed under `S`: `value` is the source's result.
    Conclusive([u8; 32]),
    /// Signed under `I(S)`: the policy's reason code (`0x01` insufficient sources, `0x02` divergence,
    /// `0x03` primary unconfirmed, `0x10 + i` the policy's `inconclusiveIf` entry `i`).
    Inconclusive(u8),
}

/// Reads a verified attestation as a result of source `S`. `None` when it is signed under neither `S`
/// nor `I(S)`, or when an `I(S)` value is not a reason code (a `uint256` from 1 to 255): reject it.
pub fn read_outcome(payload: &AttestationPayload, source_id: &[u8; 32]) -> Option<Outcome> {
    if payload.source_id == *source_id {
        return Some(Outcome::Conclusive(payload.value));
    }
    if payload.source_id == inconclusive_id(source_id)
        && payload.value[..31].iter().all(|b| *b == 0)
        && payload.value[31] != 0
    {
        return Some(Outcome::Inconclusive(payload.value[31]));
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex32(s: &str) -> [u8; 32] {
        let mut out = [0u8; 32];
        for (i, b) in out.iter_mut().enumerate() {
            *b = u8::from_str_radix(&s[2 + 2 * i..4 + 2 * i], 16).unwrap();
        }
        out
    }

    /// The node client's `new/source/testdata/policy-vectors.json`.
    #[test]
    fn matches_the_node_vectors() {
        for (s, i) in [
            (
                "0x0000000000000000000000000000000000000000000000000000000000000000",
                "0xbafadaff7889fa857773e328110d584e3d6bccb300737429d995d12e41325f0e",
            ),
            (
                "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
                "0x4e9841f5548f5348f6ae8ca7c7afb5dd230dfc0bae566aba4d4441f2e1e8cd74",
            ),
            (
                "0xe371e37c37d592464b293ce89100c4c87ddcb667b901739c60827789b200b8af",
                "0xf0f8a58c104feffc9dc7dbb32452ec9829d7d63ee8bcc1a41ba2c5784a29a9ce",
            ),
            (
                "0xd09bb3cc7c7f62b146df8c28b8408364102e78c1c2de73b02fb664019505c536",
                "0x8952b09fe2aa9346180c83243535876947d5127b603d263e1c97b7f6b7c6a160",
            ),
        ] {
            assert_eq!(inconclusive_id(&hex32(s)), hex32(i), "I({s})");
        }
    }

    fn payload(source_id: [u8; 32], value: [u8; 32]) -> AttestationPayload {
        AttestationPayload {
            value,
            source_id,
            registry_version: 1,
            signatures_required: 3,
            timestamp: 1_795_000_000_000,
        }
    }

    #[test]
    fn reads_s_as_the_result_and_i_s_as_a_reason() {
        let s = [7u8; 32];
        let mut reason = [0u8; 32];
        reason[31] = 0x02;
        assert_eq!(
            read_outcome(&payload(s, [9; 32]), &s),
            Some(Outcome::Conclusive([9; 32]))
        );
        assert_eq!(
            read_outcome(&payload(inconclusive_id(&s), reason), &s),
            Some(Outcome::Inconclusive(0x02))
        );
        // Another source, I(I(S)), and an I(S) value that is not a reason are all rejected.
        assert_eq!(read_outcome(&payload([8; 32], [9; 32]), &s), None);
        assert_eq!(
            read_outcome(&payload(inconclusive_id(&inconclusive_id(&s)), reason), &s),
            None
        );
        assert_eq!(
            read_outcome(&payload(inconclusive_id(&s), [0; 32]), &s),
            None
        );
        let mut wide = reason;
        wide[0] = 1;
        assert_eq!(read_outcome(&payload(inconclusive_id(&s), wide), &s), None);
    }
}
