//! Criterion benchmarks for VDF eval, verify, and single-iteration timing.
//!
//! Run with:
//!   cargo bench --package pso-vdf
//!
//! ## Phase 1 — Hardware Calibration
//!
//! Primary target: iPhone 13 (Apple A15 Bionic) — mobile clients compute VDF proofs.
//! Secondary reference: desktop/laptop CPUs (sequencer, verifier nodes).
//!
//! The `single_iteration` benchmark measures one x^((2p-1)/5) exponentiation.
//! From that, derive T_BASE:
//!
//!   T_BASE = target_seconds / single_iteration_time
//!
//! Example: if single iteration = 15µs → T_BASE = 2.0s / 15µs ≈ 133,333
//!
//! Since we can't run Criterion on iOS directly, measure on a comparable ARM
//! device (Apple M-series Mac) and apply a ~1.3–1.5x slowdown factor for
//! sustained mobile workloads (thermal throttling, background restrictions).

use std::hint::black_box;
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use std::time::Duration;

use ark_bls12_381::Fq;
use ark_ff::PrimeField;

use pso_vdf::{
    minroot::{self, MinRootVdf},
    types::VdfInput,
    Vdf,
};

/// Single-iteration benchmark — the fundamental unit of MinRoot cost.
///
/// This measures one `x → x^((2p-1)/5)` in BLS12-381 Fq.
/// The result directly determines the T_BASE calibration.
fn bench_single_iteration(c: &mut Criterion) {
    let x = Fq::from_le_bytes_mod_order(&[0xabu8; 32]);

    c.bench_function("minroot_single_iteration", |b| {
        b.iter(|| minroot::single_iteration(black_box(x)));
    });
}

/// Single forward iteration benchmark: x → x^5 (4 field multiplications).
///
/// This measures the cost of the forward (verification) direction.
/// Expected to be much faster than the inverse (eval) direction since
/// it's just 4 multiplications vs a full 381-bit exponentiation.
fn bench_single_forward_iteration(c: &mut Criterion) {
    let x = Fq::from_le_bytes_mod_order(&[0xabu8; 32]);

    c.bench_function("minroot_single_forward_iteration", |b| {
        b.iter(|| minroot::single_forward_iteration(black_box(x)));
    });
}

/// Difficulty sweep for eval — find the T that gives ~2 seconds.
///
/// Calibration range chosen for mobile hardware:
/// - Lower bound (~10k): fast enough for quick smoke tests
/// - Upper bound (~500k): covers the expected range for 2s on mobile
///
/// After running, look at the results to find T where eval ≈ 2.0s.
const CALIBRATION_DIFFICULTIES: &[u64] = &[
    1_000,
    5_000,
    10_000,
    50_000,
    100_000,
    200_000,
    500_000,
];

fn bench_minroot_eval(c: &mut Criterion) {
    let input = VdfInput::from_bytes([0xabu8; 32]);

    let mut group = c.benchmark_group("minroot_eval");
    group.sample_size(10); // VDF eval is intentionally slow — reduce samples
    group.measurement_time(Duration::from_secs(30));

    for &t in CALIBRATION_DIFFICULTIES {
        group.bench_with_input(
            BenchmarkId::from_parameter(t),
            &t,
            |b, &difficulty| {
                b.iter(|| MinRootVdf::eval(black_box(&input), black_box(difficulty)));
            },
        );
    }

    group.finish();
}

/// Forward verification benchmark (O(T) — 4 muls per step).
///
/// This measures `verify_forward` which computes y^(5^T) to check it equals x.
/// Much faster per-iteration than eval, but still O(T) overall.
/// Useful as a baseline for the Phase 2 proof verification target (<1ms).
fn bench_forward_verify(c: &mut Criterion) {
    let input = VdfInput::from_bytes([0xabu8; 32]);
    let difficulty = 10_000u64;
    let (output, _) = MinRootVdf::eval(&input, difficulty);

    let mut group = c.benchmark_group("minroot_forward_verify");
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(15));

    group.bench_function(BenchmarkId::from_parameter(difficulty), |b| {
        b.iter(|| {
            minroot::verify_forward(
                black_box(&input),
                black_box(&output),
                black_box(difficulty),
            )
        });
    });

    group.finish();
}

/// Wesolowski O(1) verification benchmark.
///
/// This is the Phase 2 verify path: powmod + hash_to_prime + 2 Fq exponentiations.
/// Target: <1ms on sequencer hardware (REQ-VDF-02).
fn bench_wesolowski_verify(c: &mut Criterion) {
    let input = VdfInput::from_bytes([0xabu8; 32]);
    // Use a moderate difficulty — verify time is O(1) regardless of T.
    let difficulty = 10_000u64;
    let (output, proof) = MinRootVdf::eval(&input, difficulty);

    c.bench_function("minroot_verify_wesolowski", |b| {
        b.iter(|| {
            MinRootVdf::verify(
                black_box(&input),
                black_box(&output),
                black_box(&proof),
                black_box(difficulty),
            )
        });
    });
}

criterion_group!(
    benches,
    bench_single_iteration,
    bench_single_forward_iteration,
    bench_minroot_eval,
    bench_forward_verify,
    bench_wesolowski_verify,
);
criterion_main!(benches);
