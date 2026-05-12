//! [`VdfParams`] — canonical construction of the VDF input from tx context.

use sha2::{Digest, Sha256};

use crate::types::{VdfDifficulty, VdfInput};

/// Canonical VDF input construction:
///
/// ```text
/// vdf_input = SHA-256(signer_le_20 ‖ nonce_le_8 ‖ submitted_block_le_8 ‖ chain_id_le_8)
/// ```
///
/// This is the binding the validator enforces — see
/// [`enforce-vdf-input-binding.md`](../../../../docs/issues/enforce-vdf-input-binding.md).
/// Wallets must construct `vdf_input` exactly this way, or the validator
/// rejects with `BadVdfInputBinding`.
///
/// Why these four fields:
///   * `signer` — ties the proof to a specific account; one wallet
///     can't reuse another's proof.
///   * `nonce` — ties the proof to a specific tx slot for the
///     signer; can't be reused across txs from the same account.
///   * `submitted_block` — ties the proof to a specific block window;
///     can't be stockpiled across blocks (combined with the
///     backward-looking validity window).
///   * `chain_id` — chain-specific; proof for chain A can't be
///     replayed on chain B.
///
/// We deliberately do **not** include `tx_hash` — it would create a circular
/// dependency (tx_hash covers calldata, which contains `vdf_input`). The
/// `(signer, nonce)` pair is the same identifier the EVM uses for nonce
/// ordering, so it uniquely identifies a tx slot pre-signing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VdfParams {
    /// 20-byte EVM address of the wallet computing the proof.
    pub signer: [u8; 20],
    /// EVM nonce of the transaction this proof binds to.
    pub nonce: u64,
    /// L2 block height the wallet observed when computing the proof.
    /// Validator accepts iff `current_block - submitted_block ∈ [0, MAX_AGE]`.
    pub submitted_block: u64,
    /// The EVM chain ID of the sidechain.
    pub chain_id: u64,
    /// The VDF difficulty `T` at the time of proof generation.
    ///
    /// Must match the epoch difficulty at validation time (within tolerance).
    pub difficulty: VdfDifficulty,
}

impl VdfParams {
    /// Construct a new set of VDF parameters.
    pub fn new(
        signer: [u8; 20],
        nonce: u64,
        submitted_block: u64,
        chain_id: u64,
        difficulty: VdfDifficulty,
    ) -> Self {
        Self {
            signer,
            nonce,
            submitted_block,
            chain_id,
            difficulty,
        }
    }

    /// Derive the canonical 32-byte VDF input.
    ///
    /// `vdf_input = SHA-256(signer ‖ nonce_le ‖ submitted_block_le ‖ chain_id_le)`.
    /// Wallets and validators MUST agree on this byte order; the validator
    /// rejects mismatches with `RejectionReason::BadVdfInputBinding`.
    pub fn derive_input(&self) -> VdfInput {
        Self::derive_input_from(self.signer, self.nonce, self.submitted_block, self.chain_id)
    }

    /// Free function form of [`Self::derive_input`] — useful when the
    /// validator wants to recompute the expected seed without first
    /// constructing a full `VdfParams` (it doesn't know `difficulty` at
    /// the binding-check moment).
    pub fn derive_input_from(
        signer: [u8; 20],
        nonce: u64,
        submitted_block: u64,
        chain_id: u64,
    ) -> VdfInput {
        let mut hasher = Sha256::new();
        hasher.update(signer);
        hasher.update(nonce.to_le_bytes());
        hasher.update(submitted_block.to_le_bytes());
        hasher.update(chain_id.to_le_bytes());
        let result: [u8; 32] = hasher.finalize().into();
        VdfInput::from_bytes(result)
    }

    /// Check whether a proof's `submitted_block` is within the acceptable
    /// backward-looking validity window relative to `current_block`.
    ///
    /// Accept iff `submitted_block ≤ current_block` and
    /// `current_block - submitted_block ≤ window` (see `PROOF_VALIDITY_WINDOW`
    /// in lib.rs, REQ-VDF-05).
    pub fn is_block_valid(submitted_block: u64, current_block: u64, window: u64) -> bool {
        submitted_block <= current_block && current_block - submitted_block <= window
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derive_input_is_deterministic() {
        let p = VdfParams::new([0xab; 20], 7, 100, 19280501, 1_000_000);
        assert_eq!(p.derive_input(), p.derive_input());
    }

    #[test]
    fn different_signers_produce_different_inputs() {
        let a = VdfParams::new([0x01; 20], 0, 100, 19280501, 1_000_000);
        let b = VdfParams::new([0x02; 20], 0, 100, 19280501, 1_000_000);
        assert_ne!(a.derive_input(), b.derive_input());
    }

    #[test]
    fn different_nonces_produce_different_inputs() {
        let a = VdfParams::new([0x01; 20], 0, 100, 19280501, 1_000_000);
        let b = VdfParams::new([0x01; 20], 1, 100, 19280501, 1_000_000);
        assert_ne!(a.derive_input(), b.derive_input());
    }

    #[test]
    fn different_chain_ids_produce_different_inputs() {
        let a = VdfParams::new([0x01; 20], 0, 100, 19280501, 1_000_000);
        let b = VdfParams::new([0x01; 20], 0, 100, 19280502, 1_000_000);
        assert_ne!(a.derive_input(), b.derive_input());
    }

    #[test]
    fn block_validity_window() {
        // current_block=100, window=32 — accept submitted_block ∈ [68, 100]
        assert!(VdfParams::is_block_valid(100, 100, 32)); // delta=0
        assert!(VdfParams::is_block_valid(68, 100, 32)); // delta=32 (boundary)
        assert!(!VdfParams::is_block_valid(67, 100, 32)); // delta=33, too old
        assert!(!VdfParams::is_block_valid(101, 100, 32)); // future block
    }
}
