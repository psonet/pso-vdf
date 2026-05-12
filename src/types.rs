//! Primitive types shared across VDF constructions.

use alloc::vec::Vec;

/// Number of sequential iterations `T` for the VDF.
pub type VdfDifficulty = u64;

/// 32-byte VDF input — `SHA-256(tx_hash ‖ submitted_block ‖ chain_id)`.
///
/// See [`crate::params::VdfParams::derive_input`] for canonical construction.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct VdfInput(pub [u8; 32]);

impl VdfInput {
    /// Construct from raw bytes.
    pub fn from_bytes(b: [u8; 32]) -> Self {
        Self(b)
    }

    /// View as byte slice.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// VDF output `y`.
///
/// For MinRoot: a BLS12-381 base field element serialised as 48 bytes.
/// For Wesolowski: a big-integer residue mod N serialised as variable bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct VdfOutput(pub Vec<u8>);

impl VdfOutput {
    /// Expected byte length for MinRoot output (BLS12-381 Fp element).
    pub const MINROOT_LEN: usize = 48;

    /// Construct from bytes.
    pub fn from_bytes(b: Vec<u8>) -> Self {
        Self(b)
    }
}

/// VDF proof `π` — short proof that `y = f(x, T)` without re-running `f`.
///
/// The concrete encoding depends on the construction:
/// - MinRoot:    ~144 bytes
/// - Wesolowski: ~128 bytes (RSA group element)
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct VdfProof(pub Vec<u8>);

impl VdfProof {
    /// Construct from bytes.
    pub fn from_bytes(b: Vec<u8>) -> Self {
        Self(b)
    }
}
