//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! SIMD-512 tests.

#![expect(clippy::panic, reason = "test code")]

mod common;

#[cfg(feature = "simd")]
use dash_pow::simd_hash::{consts::IV, scalar, simd};
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
#[case::zeros(false, [0u8; 128])]
#[case::ones(false, [0xFFu8; 128])]
#[case::pattern_nonfinal(false, make_block(0x42))]
#[case::pattern_final(true, make_block(0x42))]
fn compress(#[case] last: bool, #[case] block: [u8; 128]) {
  let mut h_s = IV;
  let mut h_t = IV;
  scalar::compress(&mut h_s, &block, last);
  simd::compress(&mut h_t, &block, last);
  assert_eq!(h_s, h_t, "simd_hash compress diverged (last={last})");
}

mod kat {
  use super::common;

  use dash_pow::simd_hash::scalar;
  #[cfg(feature = "simd")]
  use dash_pow::simd_hash::simd;

  #[test]
  fn scalar_nist_kat() {
    let vectors = common::load("simd");
    common::run_nist_kat("simd_hash/scalar", &vectors, scalar::hash512);
  }

  #[cfg(feature = "simd")]
  #[test]
  fn simd_nist_kat() {
    let vectors = common::load("simd");
    common::run_nist_kat("simd_hash/simd", &vectors, simd::hash512);
  }
}
