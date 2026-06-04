//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

#![expect(clippy::unwrap_used, reason = "benchmarks rely on trusted test vectors")]
#![expect(clippy::panic, reason = "shared test helpers use panic for missing vectors")]

#[path = "../tests/common/mod.rs"]
mod common;
#[cfg(feature = "k256")]
mod k256;
#[cfg(feature = "bls_ietf")]
mod bls_ietf;
#[cfg(feature = "bls_chia")]
mod bls_chia;

fn main() {
  divan::main();
}
