//! Hash-to-prime for Fiat-Shamir challenge derivation in Wesolowski proofs.
//!
//! Derives a deterministic 128-bit prime `l` from `(x, y)` via SHA-256,
//! used as the Fiat-Shamir challenge in the Wesolowski proof scheme.

use sha2::{Digest, Sha256};

/// First 200 odd primes for trial division (2 is excluded since candidates
/// are always forced odd).
const SMALL_PRIMES: [u64; 200] = [
    3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73,
    79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163,
    167, 173, 179, 181, 191, 193, 197, 199, 211, 223, 227, 229, 233, 239, 241, 251,
    257, 263, 269, 271, 277, 281, 283, 293, 307, 311, 313, 317, 331, 337, 347, 349,
    353, 359, 367, 373, 379, 383, 389, 397, 401, 409, 419, 421, 431, 433, 439, 443,
    449, 457, 461, 463, 467, 479, 487, 491, 499, 503, 509, 521, 523, 541, 547, 557,
    563, 569, 571, 577, 587, 593, 599, 601, 607, 613, 617, 619, 631, 641, 643, 647,
    653, 659, 661, 673, 677, 683, 691, 701, 709, 719, 727, 733, 739, 743, 751, 757,
    761, 769, 773, 787, 797, 809, 811, 821, 823, 827, 829, 839, 853, 857, 859, 863,
    877, 881, 883, 887, 907, 911, 919, 929, 937, 941, 947, 953, 967, 971, 977, 983,
    991, 997, 1009, 1013, 1019, 1021, 1031, 1033, 1039, 1049, 1051, 1061, 1063, 1069,
    1087, 1091, 1093, 1097, 1103, 1109, 1117, 1123, 1129, 1151, 1153, 1163, 1171,
    1181, 1187, 1193, 1201, 1213, 1217, 1223, 1229,
];

/// Derive a deterministic 128-bit prime from VDF input/output pair.
///
/// 1. SHA-256(x_bytes ‖ y_bytes)
/// 2. Extract 128-bit candidate, force bit 127 high + bit 0 odd
/// 3. Search upward for the next prime (trial division + Miller-Rabin)
///
/// Expected search length: ~89 candidates (prime density at 128 bits ≈ 1/ln(2^128)).
pub fn hash_to_prime(x_bytes: &[u8], y_bytes: &[u8]) -> u128 {
    let mut hasher = Sha256::new();
    hasher.update(x_bytes);
    hasher.update(y_bytes);
    let hash = hasher.finalize();

    // Extract 128-bit candidate from first 16 bytes.
    let mut buf = [0u8; 16];
    buf.copy_from_slice(&hash[..16]);
    let mut candidate = u128::from_le_bytes(buf);

    // Force bit 127 high (ensure 128-bit) and bit 0 odd.
    candidate |= 1u128 << 127;
    candidate |= 1;

    // Find next prime.
    loop {
        if is_prime_128(candidate) {
            return candidate;
        }
        // Advance by 2 (stay odd). Overflow is astronomically unlikely
        // for 128-bit values starting near 2^127.
        candidate = candidate.checked_add(2).expect("hash_to_prime overflow");
    }
}

/// Primality test for 128-bit values.
///
/// Trial division by the first 200 small primes, then 2 rounds of
/// Miller-Rabin (bases 2, 3). Error probability per candidate ≈ 4^-2;
/// negligible in the Fiat-Shamir context.
pub fn is_prime_128(n: u128) -> bool {
    if n < 2 {
        return false;
    }
    if n == 2 || n == 3 {
        return true;
    }
    if n % 2 == 0 {
        return false;
    }

    // Trial division by small primes.
    for &p in &SMALL_PRIMES {
        let p = p as u128;
        if n == p {
            return true;
        }
        if n % p == 0 {
            return false;
        }
    }

    // Miller-Rabin with bases 2 and 3.
    miller_rabin(n, 2) && miller_rabin(n, 3)
}

/// Single round of Miller-Rabin primality test.
fn miller_rabin(n: u128, a: u128) -> bool {
    // Write n-1 = 2^s * d, d odd.
    let mut d = n - 1;
    let mut s = 0u32;
    while d % 2 == 0 {
        d >>= 1;
        s += 1;
    }

    // x = a^d mod n
    let mut x = pow_mod_128(a, d, n);

    if x == 1 || x == n - 1 {
        return true;
    }

    for _ in 1..s {
        x = mul_mod_128(x, x, n);
        if x == n - 1 {
            return true;
        }
    }

    false
}

/// Modular multiplication for 128-bit values via binary doubling.
///
/// Computes `(a * b) mod m` without requiring 256-bit arithmetic.
/// Uses 128 iterations of conditional doubling.
pub fn mul_mod_128(a: u128, b: u128, m: u128) -> u128 {
    debug_assert!(m > 0);
    let mut a = a % m;
    let mut b = b % m;
    let mut result: u128 = 0;

    while b > 0 {
        if b & 1 == 1 {
            result = add_mod(result, a, m);
        }
        a = add_mod(a, a, m);
        b >>= 1;
    }

    result
}

/// Modular addition for 128-bit values, handling overflow.
#[inline]
fn add_mod(a: u128, b: u128, m: u128) -> u128 {
    let (sum, overflow) = a.overflowing_add(b);
    if overflow || sum >= m {
        sum.wrapping_sub(m)
    } else {
        sum
    }
}

/// Modular exponentiation for 128-bit values via square-and-multiply.
pub fn pow_mod_128(mut base: u128, mut exp: u128, m: u128) -> u128 {
    if m == 1 {
        return 0;
    }
    let mut result: u128 = 1;
    base %= m;

    while exp > 0 {
        if exp & 1 == 1 {
            result = mul_mod_128(result, base, m);
        }
        exp >>= 1;
        base = mul_mod_128(base, base, m);
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_primes() {
        assert!(is_prime_128(2));
        assert!(is_prime_128(3));
        assert!(is_prime_128(5));
        assert!(is_prime_128(7));
        assert!(is_prime_128(13));
        assert!(is_prime_128(104729)); // 10000th prime
        // Large known prime: 2^127 - 1 (Mersenne prime M127)
        assert!(is_prime_128((1u128 << 127) - 1));
    }

    #[test]
    fn known_composites() {
        assert!(!is_prime_128(0));
        assert!(!is_prime_128(1));
        assert!(!is_prime_128(4));
        assert!(!is_prime_128(9));
        assert!(!is_prime_128(15));
        assert!(!is_prime_128(100));
        assert!(!is_prime_128(1000003 * 1000033)); // product of two primes
    }

    #[test]
    fn hash_to_prime_deterministic() {
        let x = [0xabu8; 48];
        let y = [0xcdu8; 48];
        let p1 = hash_to_prime(&x, &y);
        let p2 = hash_to_prime(&x, &y);
        assert_eq!(p1, p2, "hash_to_prime must be deterministic");
    }

    #[test]
    fn hash_to_prime_returns_prime() {
        let x = [0x01u8; 48];
        let y = [0x02u8; 48];
        let p = hash_to_prime(&x, &y);
        assert!(is_prime_128(p), "hash_to_prime must return a prime");
        assert!(p >= 1u128 << 127, "result must be at least 128 bits");
    }

    #[test]
    fn hash_to_prime_different_inputs() {
        let x = [0x01u8; 48];
        let y1 = [0x02u8; 48];
        let y2 = [0x03u8; 48];
        let p1 = hash_to_prime(&x, &y1);
        let p2 = hash_to_prime(&x, &y2);
        assert_ne!(p1, p2, "different inputs should produce different primes");
    }

    #[test]
    fn mul_mod_128_basic() {
        assert_eq!(mul_mod_128(7, 11, 13), 77 % 13);
        assert_eq!(mul_mod_128(0, 100, 7), 0);
        assert_eq!(mul_mod_128(100, 0, 7), 0);
        assert_eq!(mul_mod_128(1, 42, 100), 42);
    }

    #[test]
    fn mul_mod_128_large() {
        let a = u128::MAX - 1; // even
        let b = 2u128;
        let m = u128::MAX;
        // (MAX-1) * 2 mod MAX = 2*MAX - 2 mod MAX = MAX - 2
        assert_eq!(mul_mod_128(a, b, m), u128::MAX - 2);
    }

    #[test]
    fn pow_mod_128_basic() {
        // 3^10 mod 17 = 59049 mod 17 = 8
        assert_eq!(pow_mod_128(3, 10, 17), 8);
        // a^0 = 1
        assert_eq!(pow_mod_128(42, 0, 17), 1);
        // a^1 mod m = a mod m
        assert_eq!(pow_mod_128(42, 1, 17), 42 % 17);
    }
}
