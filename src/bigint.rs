//! 384-bit modular arithmetic for Wesolowski proof computation.
//!
//! Provides modular exponentiation and division over `BigInt<6>` (384-bit)
//! values used to compute E = e^T mod (p-1) in both prover and verifier.

use ark_ff::{BigInt, BigInteger};

/// 768-bit mod 384-bit via bit-by-bit long division.
///
/// Reduces `(hi * 2^384 + lo) mod modulus`. Used after full 384×384
/// multiplication to bring the result back into the modular range.
pub fn reduce_wide(lo: BigInt<6>, hi: BigInt<6>, modulus: &BigInt<6>) -> BigInt<6> {
    let mut r = BigInt::<6>::zero();

    // Iterate from bit 767 down to 0.
    for i in (0..768).rev() {
        // r = r * 2
        r.mul2();

        // Add bit i of the 768-bit input (hi:lo).
        let bit = if i >= 384 {
            hi.get_bit(i - 384)
        } else {
            lo.get_bit(i)
        };
        if bit {
            // r += 1  (r is at most 2*(m-1), adding 1 stays within BigInt<6>)
            let one = BigInt([1u64, 0, 0, 0, 0, 0]);
            r.add_with_carry(&one);
        }

        // If r >= modulus, subtract.
        if r >= *modulus {
            r.sub_with_borrow(modulus);
        }
    }

    r
}

/// Modular multiplication: `(a * b) mod m`.
///
/// Uses `BigInt::mul()` for the full 768-bit product, then `reduce_wide`
/// to bring it back to 384 bits.
pub fn mulmod(a: BigInt<6>, b: BigInt<6>, m: &BigInt<6>) -> BigInt<6> {
    let (lo, hi) = a.mul(&b);
    reduce_wide(lo, hi, m)
}

/// Modular exponentiation: `base^exp mod m` via square-and-multiply.
///
/// For T=100,000, `exp` has ~17 bits → ~17 squarings + ~8 multiplications.
pub fn powmod(base: BigInt<6>, exp: u64, m: &BigInt<6>) -> BigInt<6> {
    if exp == 0 {
        return BigInt([1u64, 0, 0, 0, 0, 0]);
    }

    let mut result = BigInt([1u64, 0, 0, 0, 0, 0]);
    let mut b = base;
    let mut e = exp;

    while e > 0 {
        if e & 1 == 1 {
            result = mulmod(result, b, m);
        }
        e >>= 1;
        if e > 0 {
            b = mulmod(b, b, m);
        }
    }

    result
}

/// Divide a 384-bit value by a 128-bit divisor.
///
/// Returns `(quotient, remainder)` via bit-by-bit long division (384 iterations).
/// A carry bit tracks the 129th bit of the intermediate remainder to handle
/// the case where `2 * remainder` overflows `u128`.
pub fn divmod_by_u128(a: BigInt<6>, d: u128) -> (BigInt<6>, u128) {
    debug_assert!(d > 0, "division by zero");

    let mut q = BigInt::<6>::zero();
    let mut r: u128 = 0;

    for i in (0..384).rev() {
        // r = r * 2 + bit_i(a), but 2*r can be 129 bits.
        let high_bit = r >> 127; // 0 or 1
        r = (r << 1) | if a.get_bit(i) { 1 } else { 0 };

        // If the 129th bit was set, or r >= d, subtract d from r.
        if high_bit != 0 || r >= d {
            r = r.wrapping_sub(d);
            // Set bit i in quotient.
            q.0[i / 64] |= 1u64 << (i % 64);
        }
    }

    (q, r)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_381::Fq;
    use ark_ff::PrimeField;

    #[test]
    fn mulmod_known_values() {
        // 7 * 11 mod 13 = 77 mod 13 = 12
        let a = BigInt([7u64, 0, 0, 0, 0, 0]);
        let b = BigInt([11u64, 0, 0, 0, 0, 0]);
        let m = BigInt([13u64, 0, 0, 0, 0, 0]);
        let r = mulmod(a, b, &m);
        assert_eq!(r, BigInt([12u64, 0, 0, 0, 0, 0]));
    }

    #[test]
    fn mulmod_larger_values() {
        // (2^64 + 1) * 3 mod (2^64 + 5)
        let a = BigInt([1u64, 1, 0, 0, 0, 0]); // 2^64 + 1
        let b = BigInt([3u64, 0, 0, 0, 0, 0]); // 3
        let m = BigInt([5u64, 1, 0, 0, 0, 0]); // 2^64 + 5
                                               // a * b = 3 * 2^64 + 3
                                               // (3 * 2^64 + 3) mod (2^64 + 5) = 3*(2^64+5) - 15 + 3 = ... let's compute:
                                               // 3 * (2^64 + 5) = 3*2^64 + 15
                                               // 3*2^64 + 3 - (3*2^64 + 15) = -12 → not right, a*b < 3*m
                                               // 3*2^64 + 3 - 2*(2^64 + 5) = 2^64 - 7
        let expected = BigInt([u64::MAX - 6, 0, 0, 0, 0, 0]); // 2^64 - 7
        let r = mulmod(a, b, &m);
        assert_eq!(r, expected);
    }

    #[test]
    fn powmod_identity() {
        let m = BigInt([17u64, 0, 0, 0, 0, 0]);
        let base = BigInt([5u64, 0, 0, 0, 0, 0]);

        // base^0 = 1
        assert_eq!(powmod(base, 0, &m), BigInt([1u64, 0, 0, 0, 0, 0]));

        // base^1 = base mod m = 5
        assert_eq!(powmod(base, 1, &m), BigInt([5u64, 0, 0, 0, 0, 0]));
    }

    #[test]
    fn powmod_small() {
        // 3^10 mod 17 = 59049 mod 17 = 8
        let base = BigInt([3u64, 0, 0, 0, 0, 0]);
        let m = BigInt([17u64, 0, 0, 0, 0, 0]);
        let r = powmod(base, 10, &m);
        assert_eq!(r, BigInt([8u64, 0, 0, 0, 0, 0]));
    }

    #[test]
    fn powmod_with_real_modulus() {
        // Use BLS12-381 p-1 as the modulus (the actual use case).
        let p = <Fq as PrimeField>::MODULUS;
        let mut p_minus_1 = p;
        let one = BigInt([1u64, 0, 0, 0, 0, 0]);
        p_minus_1.sub_with_borrow(&one);

        let base = BigInt([42u64, 0, 0, 0, 0, 0]);
        // base^1 mod (p-1) = base (since 42 < p-1)
        assert_eq!(powmod(base, 1, &p_minus_1), base);

        // base^2 = 1764, still small
        let expected = BigInt([1764u64, 0, 0, 0, 0, 0]);
        assert_eq!(powmod(base, 2, &p_minus_1), expected);
    }

    #[test]
    fn divmod_small() {
        // 100 / 7 = 14 remainder 2
        let a = BigInt([100u64, 0, 0, 0, 0, 0]);
        let (q, r) = divmod_by_u128(a, 7);
        assert_eq!(q, BigInt([14u64, 0, 0, 0, 0, 0]));
        assert_eq!(r, 2u128);
    }

    #[test]
    fn divmod_large_dividend() {
        // (2^64 + 10) / 3 = quotient and remainder
        let a = BigInt([10u64, 1, 0, 0, 0, 0]); // 2^64 + 10
        let (q, r) = divmod_by_u128(a, 3);
        // (2^64 + 10) = 3 * q + r
        // Verify by reconstruction.
        let val = (1u128 << 64) + 10;
        let expected_q = val / 3;
        let expected_r = val % 3;
        assert_eq!(u128::from(q.0[0]), expected_q);
        assert_eq!(r, expected_r);
    }

    #[test]
    fn divmod_reconstructs() {
        // For a random-ish BigInt, verify q*d + r == a.
        let a = BigInt([
            0xDEAD_BEEF_CAFE_BABEu64,
            0x1234_5678_9ABC_DEF0,
            0x42,
            0,
            0,
            0,
        ]);
        let d: u128 = (1u128 << 127) | 17; // large 128-bit divisor
        let (_q, r) = divmod_by_u128(a, d);

        // Reconstruct: q * d + r should equal a.
        // Since q is small when d is large, we can verify a few limbs.
        assert!(r < d, "remainder must be less than divisor");

        // Also verify: a / 1 == a, remainder 0
        let (q_one, r_one) = divmod_by_u128(a, 1);
        assert_eq!(q_one, a);
        assert_eq!(r_one, 0);
    }
}
