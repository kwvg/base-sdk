//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Echo-512 tests.

#![expect(clippy::panic, reason = "test code")]

mod common;

#[cfg(feature = "simd")]
use dash_pow::echo::{scalar, simd};
#[cfg(feature = "simd")]
use rstest::rstest;

#[cfg(feature = "simd")]
fn initial_cv() -> [[u32; 4]; 8] {
  [[512, 0, 0, 0]; 8]
}

#[cfg(feature = "simd")]
fn make_block(fill: u8) -> [u8; 128] {
  let mut b = [0u8; 128];
  for (i, slot) in b.iter_mut().enumerate() {
    *slot = fill.wrapping_add(i as u8);
  }
  b
}

#[cfg(feature = "simd")]
#[rstest]
#[case::zeros([1024, 0, 0, 0], [0u8; 128])]
#[case::pattern([2048, 0, 0, 0], make_block(0xCD))]
fn compress(#[case] counter: [u32; 4], #[case] block: [u8; 128]) {
  let mut h_s = initial_cv();
  let mut h_t = h_s;
  scalar::compress(&mut h_s, &block, &counter);
  simd::compress_block(&mut h_t, &block, &counter);
  assert_eq!(h_s, h_t, "echo compress diverged");
}

mod kat {
  use super::common;

  use dash_pow::echo::scalar;
  #[cfg(feature = "simd")]
  use dash_pow::echo::simd;

  #[test]
  fn scalar_nist_kat() {
    let vectors = common::load("echo");
    common::run_nist_kat("echo/scalar", &vectors, scalar::hash512);
  }

  #[cfg(feature = "simd")]
  #[test]
  fn simd_nist_kat() {
    let vectors = common::load("echo");
    common::run_nist_kat("echo/simd", &vectors, simd::hash512);
  }
}
