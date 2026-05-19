# pso-vdf

[![crates.io](https://img.shields.io/crates/v/pso-vdf.svg)](https://crates.io/crates/pso-vdf)
[![release](https://img.shields.io/github/v/release/psonet/pso-vdf.svg)](https://github.com/psonet/pso-vdf/releases)
[![CI](https://github.com/psonet/pso-vdf/actions/workflows/ci.yml/badge.svg)](https://github.com/psonet/pso-vdf/actions/workflows/ci.yml)

`no_std`-compatible Verifiable Delay Function: **MinRoot** over the
BLS12-381 base field with **Wesolowski** O(1) proof verification.

Forces a transaction submitter to burn a configurable amount of
sequential CPU time (default ~2 s on mobile) before a verifier
accepts the work — the verifier checks the proof in well under 1 ms.
No trusted setup.

## Quick start

```rust
use pso_vdf::{VdfParams, minroot::MinRootVdf, Vdf};

// 1. Build params from the surrounding tx context. `submitted_block`
//    is the latest block the wallet has observed at the moment it
//    starts proving — NOT a pre-committed future target. The
//    validator later checks `current_block - submitted_block` falls
//    inside `PROOF_VALIDITY_WINDOW`.
let params = VdfParams::new(
    signer,           // 20-byte EVM address
    nonce,            // EVM nonce of the tx this proof binds to
    submitted_block,  // latest observed block at submission time
    chain_id,
    /* difficulty T = */ 100_000,
);

// 2. Derive the VDF input — binds the proof to
//    (signer, nonce, submitted_block, chain_id).
let input = params.derive_input();

// 3. Evaluate (slow, sequential; ~2 s on iPhone 13 at T = 100_000).
let (output, proof) = MinRootVdf::eval(&input, params.difficulty);

// 4. Verify (O(1), under 1 ms).
assert!(MinRootVdf::verify(&input, &output, &proof, params.difficulty));
```

## Features

| Feature  | Default | Pulls in                                             |
|----------|---------|------------------------------------------------------|
| `std`    | off     | `ark-*/std`, `sha2/std`, `thiserror/std` — host use  |
| `serde`  | off     | `serde` derives on `VdfInput` / `VdfOutput` / `VdfProof` |

Default build is `no_std`; mobile / embedded targets can consume the
crate as-is.

## How it works

### Evaluation (slow, by design)

MinRoot applies `x -> x^(1/5) mod p` for T iterations over the BLS12-381
base field. Each step depends on the previous one, so the work is
inherently sequential. At T=100_000 it takes ~1.4 s on a desktop core
and ~2 s on a recent phone.

### Proof generation (piggybacks on evaluation)

After computing the output `y`, the prover generates a Wesolowski proof:

1. Compute `E = e^T mod (p-1)` where `e` is the fifth-root exponent.
2. Derive a Fiat-Shamir challenge `l = hash_to_prime(x, y)` (128-bit prime).
3. Compute `pi = x^floor(E/l)` (one field exponentiation, ~14 us).

The proof is a single BLS12-381 Fq element (48 bytes).

### Verification (fast)

The verifier recomputes `E` and `l`, then checks:

```
pi^l * x^r == y    where r = E mod l
```

Two 128-bit exponentiations and one field multiplication — total
~475 us, well under a 1 ms budget.

### Why no trusted setup

MinRoot operates over BLS12-381's base field whose prime `p` is a
public standard. No secret parameters exist; security rests on the
sequentiality of iterated exponentiation, not on a hidden trapdoor.

## Anti-replay binding

VDF inputs are bound to transaction context to prevent proof reuse:

```
vdf_input = SHA-256(signer || nonce_le || submitted_block_le || chain_id_le)
```

- **signer + nonce**: ties the proof to a specific account + tx slot;
  one wallet can't reuse another's proof, and the same wallet can't
  reuse a proof across its own txs.
- **submitted_block**: the latest block the wallet observed when it
  started proving. Proofs can't be stockpiled because validity is a
  backward-only window — the validator accepts iff
  `current_block - submitted_block` is in `[0, PROOF_VALIDITY_WINDOW]`.
  Wallets that submit from older blocks just fall outside the window.
- **chain_id**: proofs can't be replayed across chains.

We deliberately do **not** include `tx_hash` in the binding — that
would create a circular dependency (the tx hash covers calldata,
which contains `vdf_input`). The `(signer, nonce)` pair is what the
EVM already uses to identify a tx slot pre-signing.

## Module layout

| Module    | Purpose                                                    |
|-----------|------------------------------------------------------------|
| `minroot` | MinRoot VDF: `eval()`, `verify()`, `verify_forward()`      |
| `bigint`  | 384-bit modular arithmetic for proof computation           |
| `prime`   | Hash-to-prime (SHA-256 + trial division + Miller-Rabin)    |
| `params`  | `VdfParams`: input derivation, block validity checks       |
| `types`   | `VdfInput`, `VdfOutput`, `VdfProof`, `VdfDifficulty`       |
| `error`   | `VdfError` enum                                            |

## Wire format

| Field             | Size       | Description                                                                       |
|-------------------|------------|-----------------------------------------------------------------------------------|
| `vdf_input`       | 32 bytes   | `SHA-256(signer \|\| nonce_le \|\| submitted_block_le \|\| chain_id_le)`          |
| `vdf_output`      | 48 bytes   | BLS12-381 Fq element (compressed)                                                 |
| `vdf_proof`       | 48 bytes   | Wesolowski witness pi (one Fq element)                                            |
| `vdf_difficulty`  | 8 bytes    | `u64` iteration count T                                                           |
| `submitted_block` | 8 bytes    | `u64` block number — the latest block the wallet observed at submission time      |

## Building and testing

```bash
# Build (no_std by default)
cargo build

# Build with std
cargo build --features std

# Build with serde derives on wire types
cargo build --features serde

# Run tests
cargo test --all-features

# Run benchmarks (requires nightly Criterion)
cargo bench
```

## Benchmarks

| Benchmark                          | What it measures                                       |
|------------------------------------|--------------------------------------------------------|
| `minroot_single_iteration`         | One x^e step (~13.7 us) — calibration unit             |
| `minroot_single_forward_iteration` | One x^5 step (~73 ns)                                  |
| `minroot_eval/{T}`                 | Full eval at various T values                          |
| `minroot_forward_verify/{T}`       | O(T) forward-verification baseline                     |
| `minroot_verify_wesolowski`        | O(1) Wesolowski verification (target: under 1 ms)      |

## License

Licensed under the MIT license. See [`LICENSE`](LICENSE).
