//! Known-answer vectors for the on-the-wire MinRoot bytes.
//!
//! `VdfOutput` and `MinRootProof` are consensus data: the node's anti-spam
//! lane accepts or rejects a transaction on these exact bytes, so a change to
//! how a BLS12-381 `Fq` serializes is a chain split, not a refactor. Every
//! other test in this crate is a roundtrip or a determinism check, and those
//! stay green through such a change — only pinned bytes catch it.
//!
//! Captured under arkworks 0.5 and re-verified unchanged under 0.6.
//!
//! A failure here means the serialization moved. Do NOT re-bless these values
//! without establishing that every deployed node moved with them.

use pso_vdf::{minroot::MinRootVdf, Vdf, VdfInput};

/// `(difficulty, output_hex, proof_hex)` for `VdfInput([7u8; 32])`.
const VECTORS: &[(u64, &str, &str)] = &[
    (
        1,
        "a50b04897a0ca789dee329ecf0094de845aa9d3d1825093fb6007e6bf9760b0536b6d5c0c04567b21fa66d2ee26b820e",
        "df9f7f8bf723a3ce0fd6420690638eee266e0c0d5810aca7f3b23598199354a5ac13b2d85ad468f9f209bd406310410f",
    ),
    (
        7,
        "cd292f83f6afcef8d82b4ca94e35bbe56d5755304265d9cd77e3c82d9e312dbb8412c6d583cf9d96691bcef7152e4716",
        "6c751ddc6a89dc0c374401e453c579075a0dd3bb9f6b04438f7772d6ac10ba3e1ef0f1a56043afda710bf7ff7202b106",
    ),
    (
        64,
        "5c49220ef099eac23521ebce6acf268fe01f46889d127a382eabb5170b3ca1320cd2ea102d5de4852b2e379450c51e01",
        "6892dcebdfe112a96c5feadacf1ffbafd7d85229a8813f91d23aca14a4ad5645f5c3d1767e0c87d5675f7f19621d3c18",
    ),
];

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[test]
fn minroot_wire_bytes_are_pinned() {
    let input = VdfInput::from_bytes([7u8; 32]);
    for &(difficulty, want_out, want_proof) in VECTORS {
        let (out, proof) = MinRootVdf::eval(&input, difficulty);
        assert_eq!(
            hex(&out.0),
            want_out,
            "output bytes moved at d={difficulty}"
        );
        assert_eq!(
            hex(&proof.inner),
            want_proof,
            "proof bytes moved at d={difficulty}"
        );
    }
}
