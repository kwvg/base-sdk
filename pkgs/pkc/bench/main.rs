//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

#![expect(clippy::unwrap_used, reason = "benchmarks rely on trusted test vectors")]

use divan::main as run;

#[cfg(feature = "bls")]
mod bls_chia;
#[cfg(feature = "bls")]
mod bls_ietf;
#[cfg(feature = "k256")]
mod k256;

fn main() {
  run();
}
