//! MinRoot VDF over the BLS12-381 base field (Fp) with Wesolowski O(1) verification.
//!
//! ## Algorithm outline
//!
//! MinRoot is defined as iterated application of the "fifth-root" map in Fp:
//!
//! ```text
//! x_{i+1} = x_i^(1/5)  mod p     (where p is the BLS12-381 base field prime)
//! ```
//!
//! Since `gcd(5, p-1) = 1` for the BLS12-381 prime (p ≡ 2 mod 5, so p-1 ≡ 1
//! mod 5), the fifth root is a permutation of Fp and the inverse exponent
//! `e = (4p - 3) / 5` is well-defined.
//!
//! After `T` iterations the output is `y = x_T`.
//!
//! ## Wesolowski proof (Phase 2)
//!
//! Key insight: T iterations of `f(x) = x^e` equals a single exponentiation
//! `y = x^E` where `E = e^T mod (p-1)`. This enables a Wesolowski proof:
//!
//! - Prover computes `π = x^⌊E/l⌋` where `l = hash_to_prime(x, y)`
//! - Verifier checks `π^l · x^r == y` where `r = E mod l`
//! - Two 128-bit exponentiations + 1 multiplication ≈ O(1) verification
//!
//! ## References
//!
//! - Ethereum research MinRoot VDF: <https://ethresear.ch/t/minroot-vdf/4920>
//! - Wesolowski 2019: Efficient verifiable delay functions

use alloc::vec::Vec;

use ark_bls12_381::Fq;
use ark_ff::{BigInt, BigInteger, Field, PrimeField};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

use crate::{
    bigint::{divmod_by_u128, powmod},
    error::VdfError,
    prime::hash_to_prime,
    types::{VdfDifficulty, VdfInput, VdfOutput},
    Vdf,
};

/// MinRoot VDF over BLS12-381 Fp.
pub struct MinRootVdf;

/// MinRoot-specific proof type.
///
/// Contains a single serialised Fq element `π` (48 bytes) — the Wesolowski
/// proof witness.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MinRootProof {
    /// Serialised proof bytes (48 bytes: one BLS12-381 Fq element).
    pub inner: Vec<u8>,
}

impl MinRootProof {
    /// Deserialise from raw bytes.
    pub fn from_bytes(b: Vec<u8>) -> Result<Self, VdfError> {
        if b.is_empty() {
            return Err(VdfError::MalformedProof {
                reason: "empty proof bytes",
            });
        }
        Ok(Self { inner: b })
    }
}

/// Compute the fifth-root exponent and return it.
fn inv5_exponent() -> <Fq as PrimeField>::BigInt {
    compute_inv5_exponent()
}

/// Compute `p - 1` for the BLS12-381 base field.
fn compute_p_minus_1() -> BigInt<6> {
    let mut p = <Fq as PrimeField>::MODULUS;
    let one = BigInt([1u64, 0, 0, 0, 0, 0]);
    p.sub_with_borrow(&one);
    p
}

/// Serialise an Fq element to compressed bytes.
fn serialize_fq(x: &Fq) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(48);
    x.serialize_compressed(&mut bytes)
        .expect("serialisation of Fq element cannot fail");
    bytes
}

impl Vdf for MinRootVdf {
    type Proof = MinRootProof;

    fn eval(input: &VdfInput, difficulty: VdfDifficulty) -> (VdfOutput, MinRootProof) {
        if difficulty == 0 {
            panic!("difficulty must be > 0");
        }

        // Derive an Fq element from the 32-byte input.
        let x_orig: Fq = Fq::from_le_bytes_mod_order(input.as_bytes());

        // Core iteration: x_{i+1} = x_i^inv5
        let inv5 = inv5_exponent();
        let mut x = x_orig;
        for _ in 0..difficulty {
            x = x.pow(inv5.as_ref());
        }
        let y = x;

        // Serialise output and input for proof computation.
        let output_bytes = serialize_fq(&y);
        let x_bytes = serialize_fq(&x_orig);

        // --- Wesolowski proof computation ---
        // E = e^T mod (p-1)
        let p_minus_1 = compute_p_minus_1();
        let e_big = powmod(inv5, difficulty, &p_minus_1);

        // l = hash_to_prime(x, y)
        let l = hash_to_prime(&x_bytes, &output_bytes);

        // π = x^⌊E/l⌋
        let (q, _r) = divmod_by_u128(e_big, l);
        let pi = x_orig.pow(q.0.as_ref());

        let proof_bytes = serialize_fq(&pi);
        let proof = MinRootProof { inner: proof_bytes };
        (VdfOutput::from_bytes(output_bytes), proof)
    }

    fn verify(
        input: &VdfInput,
        output: &VdfOutput,
        proof: &MinRootProof,
        difficulty: VdfDifficulty,
    ) -> bool {
        if difficulty == 0 {
            return false;
        }

        // Deserialise x, y, π.
        let x: Fq = Fq::from_le_bytes_mod_order(input.as_bytes());
        let y: Fq = match Fq::deserialize_compressed(output.0.as_slice()) {
            Ok(val) => val,
            Err(_) => return false,
        };
        let pi: Fq = match Fq::deserialize_compressed(proof.inner.as_slice()) {
            Ok(val) => val,
            Err(_) => return false,
        };

        // Canonical serialisation for hash_to_prime (must match eval).
        let x_bytes = serialize_fq(&x);
        let y_bytes = serialize_fq(&y);

        // E = e^T mod (p-1)
        let inv5 = inv5_exponent();
        let p_minus_1 = compute_p_minus_1();
        let e_big = powmod(inv5, difficulty, &p_minus_1);

        // l = hash_to_prime(x, y)
        let l = hash_to_prime(&x_bytes, &y_bytes);

        // E = q*l + r
        let (_q, r) = divmod_by_u128(e_big, l);

        // Check: pi^l * x^r == y
        let l_limbs = [l as u64, (l >> 64) as u64];
        let r_limbs = [r as u64, (r >> 64) as u64];
        let pi_l = pi.pow(l_limbs);
        let x_r = x.pow(r_limbs);

        pi_l * x_r == y
    }
}

/// Verify a MinRoot chain by running the *forward* direction.
///
/// Given output `y`, compute `y^5` for `T` iterations and check that the
/// result equals `x`. This is O(T) but uses only field multiplication (no
/// exponentiation), so it is faster than re-running eval.
///
/// Useful for testing correctness — provides an independent oracle to
/// cross-check the Wesolowski proof.
pub fn verify_forward(input: &VdfInput, output: &VdfOutput, difficulty: VdfDifficulty) -> bool {
    let x: Fq = Fq::from_le_bytes_mod_order(input.as_bytes());

    let y: Fq = match Fq::deserialize_compressed(output.0.as_slice()) {
        Ok(val) => val,
        Err(_) => return false,
    };

    // Forward check: y^(5^T) should equal x.
    // Each step: z = z^5 (4 multiplications).
    let mut z = y;
    for _ in 0..difficulty {
        z = single_forward_iteration(z);
    }

    z == x
}

/// Compute the fifth-root exponent for the BLS12-381 Fp field.
///
/// We need `e` such that `5 * e ≡ 1 (mod p - 1)`, i.e. `x → x^e` is the
/// unique fifth-root map on Fq*.
///
/// For BLS12-381, `p ≡ 2 (mod 5)`, so `p - 1 ≡ 1 (mod 5)`. The inverse of
/// 5 modulo `(p - 1)` is:
///
///   `e = (4 * (p - 1) + 1) / 5 = (4p - 3) / 5`
///
/// Verification: `5e = 4p - 3 = 4(p-1) + 1 ≡ 1 (mod p-1)`. ✓
fn compute_inv5_exponent() -> <Fq as PrimeField>::BigInt {
    let p = <Fq as PrimeField>::MODULUS;

    // Step 1: compute 4p.
    // We work in 7 limbs to handle potential overflow (4p can be up to 383 bits).
    let mut four_p = [0u64; 7];
    let mut carry = 0u128;
    for (i, limb) in four_p.iter_mut().enumerate().take(6) {
        let wide = u128::from(p.0[i]) * 4 + carry;
        *limb = wide as u64;
        carry = wide >> 64;
    }
    four_p[6] = carry as u64;

    // Step 2: subtract 3 -> (4p - 3)
    let mut borrow = 3u64;
    for limb in &mut four_p {
        let (val, b) = limb.overflowing_sub(borrow);
        *limb = val;
        borrow = u64::from(b);
        if borrow == 0 {
            break;
        }
    }

    // Step 3: divide by 5 (schoolbook long division, MSB to LSB)
    let mut result = [0u64; 7];
    let mut remainder = 0u128;
    for i in (0..7).rev() {
        let dividend = (remainder << 64) | u128::from(four_p[i]);
        result[i] = (dividend / 5) as u64;
        remainder = dividend % 5;
    }
    debug_assert_eq!(remainder, 0, "(4p - 3) is not divisible by 5");
    // The result fits in 6 limbs because e < p.
    debug_assert_eq!(result[6], 0, "inv5 exponent overflows 6 limbs");

    ark_ff::BigInt([
        result[0], result[1], result[2], result[3], result[4], result[5],
    ])
}

/// Perform a single fifth-root iteration: `x → x^e`.
///
/// Exposed for benchmarking the cost of one iteration, which directly
/// determines the relationship between difficulty `T` and wall-clock time.
pub fn single_iteration(x: Fq) -> Fq {
    let inv5 = inv5_exponent();
    x.pow(inv5.as_ref())
}

/// Perform a single forward (fifth-power) iteration: `x → x^5`.
///
/// This is the inverse of the fifth-root and is used in forward verification.
/// Costs only 4 field multiplications (faster than the exponentiation in eval).
pub fn single_forward_iteration(x: Fq) -> Fq {
    let x2 = x * x;
    let x4 = x2 * x2;
    x4 * x
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn inv5_exponent_is_nonzero() {
        let e = compute_inv5_exponent();
        assert!(
            e.0.iter().any(|&limb| limb != 0),
            "inv5 exponent must be nonzero"
        );
    }

    #[test]
    fn p_mod_5_is_2() {
        // Sanity check our assumption about the BLS12-381 prime.
        let p = <Fq as PrimeField>::MODULUS;
        let mut rem = 0u128;
        for i in (0..6).rev() {
            rem = (rem << 64) | u128::from(p.0[i]);
            rem %= 5;
        }
        assert_eq!(rem, 2, "BLS12-381 Fq prime must be == 2 (mod 5)");
    }

    #[test]
    fn fifth_root_roundtrip() {
        let x = Fq::from(42u64);
        let inv5 = compute_inv5_exponent();
        let root = x.pow(inv5.as_ref());
        let restored = single_forward_iteration(root);
        assert_eq!(x, restored, "x^(e) raised to 5th power must return x");
    }

    #[test]
    fn fifth_root_roundtrip_multiple_values() {
        let inv5 = compute_inv5_exponent();
        for val in [1u64, 2, 7, 1337, u64::MAX] {
            let x = Fq::from(val);
            let root = x.pow(inv5.as_ref());
            let restored = single_forward_iteration(root);
            assert_eq!(x, restored, "roundtrip failed for val={val}");
        }
    }

    #[test]
    fn fifth_root_of_one_is_one() {
        let inv5 = compute_inv5_exponent();
        let one = Fq::from(1u64);
        let root = one.pow(inv5.as_ref());
        assert_eq!(root, one, "fifth root of 1 must be 1");
    }

    #[test]
    fn eval_produces_deterministic_output() {
        let input = VdfInput::from_bytes([0xabu8; 32]);
        let t = 100u64;
        let (out1, _) = MinRootVdf::eval(&input, t);
        let (out2, _) = MinRootVdf::eval(&input, t);
        assert_eq!(out1, out2, "eval must be deterministic");
    }

    #[test]
    fn different_inputs_give_different_outputs() {
        let a = VdfInput::from_bytes([0x01u8; 32]);
        let b = VdfInput::from_bytes([0x02u8; 32]);
        let t = 100u64;

        let (out_a, _) = MinRootVdf::eval(&a, t);
        let (out_b, _) = MinRootVdf::eval(&b, t);
        assert_ne!(out_a, out_b);
    }

    #[test]
    fn different_difficulties_give_different_outputs() {
        let input = VdfInput::from_bytes([0xffu8; 32]);
        let (out1, _) = MinRootVdf::eval(&input, 50);
        let (out2, _) = MinRootVdf::eval(&input, 100);
        assert_ne!(out1, out2);
    }

    #[test]
    fn eval_verify_roundtrip() {
        let input = VdfInput::from_bytes([0xdeu8; 32]);
        let t = 100u64;
        let (output, proof) = MinRootVdf::eval(&input, t);
        assert!(MinRootVdf::verify(&input, &output, &proof, t));
    }

    #[test]
    fn verify_rejects_wrong_output() {
        let input = VdfInput::from_bytes([0xdeu8; 32]);
        let t = 100u64;
        let (_output, proof) = MinRootVdf::eval(&input, t);
        let wrong_output = VdfOutput::from_bytes(vec![0u8; 48]);
        assert!(!MinRootVdf::verify(&input, &wrong_output, &proof, t));
    }

    #[test]
    fn verify_rejects_wrong_difficulty() {
        let input = VdfInput::from_bytes([0xdeu8; 32]);
        let (output, proof) = MinRootVdf::eval(&input, 100);
        assert!(!MinRootVdf::verify(&input, &output, &proof, 50));
    }

    #[test]
    fn verify_rejects_wrong_proof() {
        let input = VdfInput::from_bytes([0xdeu8; 32]);
        let t = 100u64;
        let (output, _proof) = MinRootVdf::eval(&input, t);
        let wrong_proof = MinRootProof {
            inner: vec![0u8; 48],
        };
        assert!(!MinRootVdf::verify(&input, &output, &wrong_proof, t));
    }

    #[test]
    fn forward_verification_matches_eval() {
        let input = VdfInput::from_bytes([0xabu8; 32]);
        let t = 100u64;
        let (output, _) = MinRootVdf::eval(&input, t);
        assert!(verify_forward(&input, &output, t));
    }

    #[test]
    fn forward_verification_rejects_wrong_output() {
        let input = VdfInput::from_bytes([0xabu8; 32]);
        let wrong_output = VdfOutput::from_bytes(vec![0u8; 48]);
        assert!(!verify_forward(&input, &wrong_output, 100));
    }

    #[test]
    fn verify_zero_difficulty_returns_false() {
        let input = VdfInput::from_bytes([0x01u8; 32]);
        let output = VdfOutput::from_bytes(vec![0u8; 48]);
        let proof = MinRootProof {
            inner: vec![0u8; 48],
        };
        assert!(!MinRootVdf::verify(&input, &output, &proof, 0));
    }

    #[test]
    fn wesolowski_verify_cross_check_with_forward() {
        // Both Wesolowski O(1) verify and O(T) forward verify should agree.
        let input = VdfInput::from_bytes([0x42u8; 32]);
        let t = 50u64;
        let (output, proof) = MinRootVdf::eval(&input, t);

        assert!(MinRootVdf::verify(&input, &output, &proof, t));
        assert!(verify_forward(&input, &output, t));
    }

    #[test]
    fn proof_is_48_bytes() {
        let input = VdfInput::from_bytes([0xabu8; 32]);
        let (_output, proof) = MinRootVdf::eval(&input, 10);
        assert_eq!(
            proof.inner.len(),
            48,
            "Wesolowski proof must be 48 bytes (one Fq element)"
        );
    }
}
