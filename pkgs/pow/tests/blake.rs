//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Blake-512 tests.

#![expect(clippy::panic, reason = "test code")]

mod common;

#[cfg(all(feature = "_internal", feature = "simd"))]
use dash_pow::blake::{consts::IV, scalar, simd};
#[cfg(all(feature = "_internal", feature = "simd"))]
use rstest::rstest;

/// Scalar compress takes `&[u8]` and loads BE words internally. SIMD compress
/// takes pre-loaded `&[u64; 16]` words. We bridge via `simd::load_message` to
/// get the same word view.
#[cfg(all(feature = "_internal", feature = "simd"))]
#[rstest]
#[case::zeros([0u8; 128], 1024, 0)]
#[case::pattern({
  let mut b = [0u8; 128];
  let mut i = 0;
  while i < 128 { b[i] = (i as u8).wrapping_mul(7); i += 1; }
  b
}, 1024, 0)]
#[case::counter_wrap([0xAAu8; 128], u64::MAX - 512, 0)]
fn compress(#[case] block: [u8; 128], #[case] t0: u64, #[case] t1: u64) {
  let mut h_scalar = IV;
  let mut h_simd = IV;
  scalar::compress(&mut h_scalar, &block, t0, t1);
  let words = simd::load_message(&block);
  simd::compress(&mut h_simd, &words, t0, t1);
  assert_eq!(h_scalar, h_simd, "blake compress diverged");
}

#[cfg(feature = "_internal")]
mod kat {
  use crate::common;

  use dash_pow::blake::scalar;
  #[cfg(feature = "simd")]
  use dash_pow::blake::simd;

  #[test]
  fn scalar() {
    let vectors = common::load("blake");
    common::run_nist_kat("blake/scalar", &vectors, scalar::hash512);
  }

  #[cfg(feature = "simd")]
  #[test]
  fn simd() {
    let vectors = common::load("blake");
    common::run_nist_kat("blake/simd", &vectors, simd::hash512);
  }
}
