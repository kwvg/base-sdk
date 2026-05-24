//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! SHAvite-3-512 tests.

#![expect(clippy::panic, reason = "test code")]

mod common;

#[cfg(feature = "simd")]
use dash_pow::shavite::{consts::IV, scalar, simd};
#[cfg(feature = "simd")]
use rstest::rstest;

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
#[case::zeros([1u32, 0, 0, 0], [0u8; 128])]
#[case::pattern([2, 0, 0, 0], make_block(0xAB))]
fn compress(#[case] counter: [u32; 4], #[case] block: [u8; 128]) {
  let mut h_s = IV;
  let mut h_t = IV;
  scalar::compress(&mut h_s, &block, &counter);
  simd::compress_block(&mut h_t, &block, &counter);
  assert_eq!(h_s, h_t, "shavite compress diverged");
}

mod kat {
  use super::common;

  use dash_pow::shavite::scalar;
  #[cfg(feature = "simd")]
  use dash_pow::shavite::simd;

  #[test]
  fn scalar_nist_kat() {
    let vectors = common::load("shavite");
    common::run_nist_kat("shavite/scalar", &vectors, scalar::hash512);
  }

  #[cfg(feature = "simd")]
  #[test]
  fn simd_nist_kat() {
    let vectors = common::load("shavite");
    common::run_nist_kat("shavite/simd", &vectors, simd::hash512);
  }
}
