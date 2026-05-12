//! # pso-vdf
//!
//! `no_std`-compatible Verifiable Delay Function primitives for pso-chain.
//!
//! ## Algorithm
//!
//! MinRoot VDF over BLS12-381 Fq with Wesolowski O(1) proof scheme.
//! No trusted setup required.
//!
//! ## Usage
//!
//! ```rust,ignore
//! use pso_vdf::{VdfParams, minroot::MinRootVdf, Vdf};
//!
//! let params = VdfParams::new(CHAIN_ID, TARGET_BLOCK, DIFFICULTY_T);
//! let input  = params.derive_input(&tx_hash);
//! let (output, proof) = MinRootVdf::eval(&input, params.difficulty);
//! assert!(MinRootVdf::verify(&input, &output, &proof, params.difficulty));
//! ```
//!
//! ## Security note
//!
//! The `T_base` constant below is a placeholder. It MUST be calibrated on
//! reference hardware (Intel Core i5 2020) before testnet deployment.
//! See OQ-01 and Phase 1 of the roadmap.

#![cfg_attr(not(feature = "std"), no_std)]
#![warn(missing_docs, unreachable_pub)]
#![deny(unused_must_use)]

extern crate alloc;

pub mod bigint;
pub mod error;
pub mod minroot;
pub mod params;
pub mod prime;
pub mod types;

// Re-export the main traits and types at crate root for convenience.
pub use error::VdfError;
pub use params::VdfParams;
pub use types::{VdfDifficulty, VdfInput, VdfOutput, VdfProof};

/// Core VDF trait.
///
/// All operations are `no_std` compatible. The `eval` function is slow by
/// design (O(T) sequential steps). The `verify` function is fast (O(1)).
pub trait Vdf: Sized {
    /// The proof type specific to this VDF construction.
    type Proof;

    /// Evaluate the VDF: compute `(y, π) = f(x, T)`.
    ///
    /// This is the slow path — it takes approximately `T_base` seconds on
    /// reference hardware. Callers should run this off the hot path (e.g.
    /// in a background thread or async task before broadcasting a tx).
    fn eval(input: &VdfInput, difficulty: VdfDifficulty) -> (VdfOutput, Self::Proof);

    /// Verify a VDF proof: check that `π` proves `y = f(x, T)`.
    ///
    /// This must complete in under 1ms on sequencer hardware (REQ-VDF-02).
    fn verify(
        input: &VdfInput,
        output: &VdfOutput,
        proof: &Self::Proof,
        difficulty: VdfDifficulty,
    ) -> bool;
}

/// Base difficulty constant — calibrated for ~2 seconds on iPhone 13 (A15 Bionic).
///
/// Calibration (Phase 1 benchmarks on Apple Silicon, ark-bls12-381 0.5):
///   - Single MinRoot iteration: ~13.7 µs
///   - T=100,000 → ~1.40s (desktop) → ~1.95s (iPhone 13, 1.4x thermal factor)
///
/// The epoch difficulty adjustment can scale T up/down by ±25% from this base
/// depending on mempool pressure (see `DifficultyState::adjust`).
///
/// This value should be re-confirmed on actual iPhone 13 hardware before
/// mainnet launch. The 1.4x mobile factor is an estimate based on sustained
/// workload thermal throttling.
pub const T_BASE: VdfDifficulty = 100_000;

/// Maximum difficulty adjustment per epoch (±25%).
pub const MAX_DIFFICULTY_ADJUSTMENT_PCT: u64 = 25;

/// Epoch length in L2 blocks.
pub const EPOCH_LENGTH_BLOCKS: u64 = 128;

/// VDF proof validity window in blocks (±32 from target).
pub const PROOF_VALIDITY_WINDOW: u64 = 32;
