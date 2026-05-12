//! Error types for pso-vdf.

use thiserror::Error;

/// Errors that can arise during VDF verification.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum VdfError {
    /// The VDF proof bytes are malformed (wrong length or invalid encoding).
    #[error("malformed proof: {reason}")]
    MalformedProof {
        /// Human-readable description.
        reason: &'static str,
    },

    /// The VDF output bytes are malformed.
    #[error("malformed output: {reason}")]
    MalformedOutput {
        /// Human-readable description.
        reason: &'static str,
    },

    /// Proof verification failed — the proof does not attest to the claimed output.
    #[error("proof verification failed")]
    VerificationFailed,

    /// The difficulty value is zero or otherwise invalid.
    #[error("invalid difficulty: {0}")]
    InvalidDifficulty(u64),

    /// Arkworks serialisation error wrapper.
    #[error("serialisation error")]
    Serialisation,
}
