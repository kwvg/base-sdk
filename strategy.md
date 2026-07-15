# base-sdk Adoption Strategy

Can `rust-dashcore` start depending on `base-sdk` soon, and how do we get
`base-sdk` used in the wild before the project loses momentum?

## Verdict

**Wholesale adoption** — `dashcore` depending on `base-sdk` for its primitives —
**is not feasible soon** (multiple quarters, and only with deliberate
investment). **A narrow, leaf-crate dependency edge is feasible now**, and that
is the move that demonstrates real-world use.

The two projects are on better footing than they appear. `base-sdk` being
stable-compatible and mainnet-validated removes the objections you would expect
to be fatal. What remains is a *coupling* problem, not a *quality* problem.

## Facts that de-risk this

- **`base-sdk` builds on stable Rust.** The only nightly requirement
  (`portable_simd`) is gated behind the non-default `simd` feature
  (`#![cfg_attr(feature = "simd", feature(portable_simd))]` in
  `pkgs/pow/src/lib.rs`). With `simd` off, the whole SDK compiles on stable, so
  `rust-dashcore` on stable 1.95 would **not** be forced onto nightly.
- **`base-sdk` is not unverified.** It ships per-algorithm X11 corpus vectors,
  per-payload consensus corpus (JSON5), a `chain.rs` test, and `bspcheck` has
  replayed the full mainnet and testnet3 chains. That is meaningful evidence of
  consensus-correctness.
- **std-depends-on-`no_std`+alloc is fine.** `base-sdk` being `no_std` is not a
  blocker for a std consumer.

## Why wholesale adoption is blocked

| Blocker | Detail | Severity |
|---|---|---|
| **Type identity welded to the public API** | `dashcore::Transaction` et al. carry hand-written `impl Encodable/Decodable` and are the public surface for `key-wallet`, `dash-spv`, `rpc-json`, all FFI, and external consumers. Replacing them with `dash-primitives` types breaks every one of those. | High |
| **Codec plumbing differs** | rust-dashcore = `consensus::{Encodable,Decodable}` + `bincode 2`; base-sdk = its own `Codec` trait. Encodings are consensus-correct on both sides, but consumption is via *conversion bridges*, not substitution. | High |
| **Crypto backend divergence** | dash/key-wallet use `secp256k1` 0.30 (C) + `blsful`; base-sdk `pkc` uses `k256` + `blst`. Adopting `pkc` changes key types across the wallet stack. | High (makes `pkc` a poor first target) |
| **Coverage gaps** | base-sdk has no taproot, sighash, PSBT-support types, bloom/qrinfo messages, or the SML *verification engine* that `dash-spv` relies on. It cannot be a drop-in even for the `dash` core. | Medium |
| **0.0.0 churn** | Depending on a pre-release, actively-refactored crate needs a pinned rev or vendoring. | Low / manageable |

## The feasible path: `dash-pow` as the beachhead

One integration is low-surface, low-risk, high-value, and shippable as a single
PR: **replace the C `rs-x11-hash` dependency with base-sdk's pure-Rust
`dash-pow`.**

Why this one:

- The consumer is a **single 144-line module** — `hashes/src/hash_x11.rs` — with
  essentially one call site: `rs_x11_hash::get_x11_hash(buf)`. base-sdk's
  `dash_pow::hash(&[u8]) -> Hash256` is a direct functional equivalent.
- X11 hashing is an **internal function returning 32 bytes** — no type-identity
  leak into dash's public API, unlike primitives or crypto keys.
- It is **trivially differential-testable**: run both over the same inputs and
  assert byte-equality (base-sdk already ships per-algorithm corpus vectors to
  seed this).
- It **removes a liability rust-dashcore already flags**: `rs-x11-hash` is a C
  library pulled from a GitHub fork the project does not own on crates.io
  (called out in their root `Cargo.toml`). Swapping it for owned, pure-Rust,
  no-C code is a net win independent of any broader migration.
- It is stable-compatible (`dash-pow` default features, no `simd`).

This single edge gets base-sdk **used in the wild inside the flagship
consumer** — the concrete thing that changes the funding conversation.

## Suggested sequencing

1. **Now / low-risk:** `dash-pow` replaces `rs-x11-hash` in the `hashes` crate's
   `x11` feature. One PR, differential-tested. *This is the survival move.*
2. **Next / medium:** `dash-num` (Arith256, CompactTarget, hash blobs). Useful
   but higher friction because hash types (`Txid`, `BlockHash`) leak into the
   public API and the consensus traits; likely adopted via a bridge, not a
   replacement.
3. **Long-horizon / needs a strategy first:** `primitives`, `pkc`, `p2p_core`.
   These require resolving the trait/type-identity story (a re-export migration
   with a wire-compat proof, analogous to the `bitcoin 0.32` migration
   rust-dashcore's `ANALYSIS.md` already contemplates) and closing the coverage
   gaps. Not soon.

## Bottom line

Do not argue for wholesale adoption — the coupling costs lose that case. Land
the **`dash-pow`-for-`rs-x11-hash` swap**: a few hundred lines, a clean win
rust-dashcore benefits from regardless of any broader migration, and it converts
base-sdk from "incubated but unused" to "shipping in dashcore's hashing path."
From there, `num` and a formal re-export strategy become the follow-on case.
