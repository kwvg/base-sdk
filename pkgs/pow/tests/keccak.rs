//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Keccak-512 tests.

#![expect(clippy::panic, reason = "test code")]

mod common;

#[cfg(feature = "simd")]
use dash_pow::keccak::{scalar, simd};
#[cfg(feature = "simd")]
use rstest::rstest;

#[cfg(feature = "simd")]
#[rstest]
#[case::zeros(0u64)]
#[case::pattern(0xdead_beef_cafe_babe)]
#[case::sequential(0x0123_4567_89ab_cdef)]
#[case::max(u64::MAX)]
fn keccak_f1600(#[case] seed: u64) {
  let mut s = [0u64; 25];
  for (i, slot) in s.iter_mut().enumerate() {
    *slot = seed.wrapping_mul(i as u64).wrapping_add(i as u64);
  }
  let mut t = s;
  scalar::keccak_f1600(&mut s);
  simd::keccak_f1600(&mut t);
  assert_eq!(s, t, "keccak_f1600 diverged with seed {seed:#x}");
}

mod kat {
  use super::common;

  use dash_pow::keccak::scalar;
  #[cfg(feature = "simd")]
  use dash_pow::keccak::simd;

  #[test]
  fn scalar_nist_kat() {
    let vectors = common::load("keccak");
    common::run_nist_kat("keccak/scalar", &vectors, scalar::hash512);
  }

  #[cfg(feature = "simd")]
  #[test]
  fn simd_nist_kat() {
    let vectors = common::load("keccak");
    common::run_nist_kat("keccak/simd", &vectors, simd::hash512);
  }
}
