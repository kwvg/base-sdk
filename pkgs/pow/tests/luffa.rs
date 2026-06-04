//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Luffa-512 tests.

#![expect(clippy::panic, reason = "test code")]

mod common;

#[cfg(feature = "simd")]
use dash_pow::luffa::{consts::IV, scalar, simd};
#[cfg(feature = "simd")]
use rstest::rstest;

#[cfg(feature = "simd")]
fn make_state(seed: u32) -> [[u32; 8]; 5] {
  let mut s = IV;
  if seed != 0 {
    for (c, row) in s.iter_mut().enumerate() {
      for (w, slot) in row.iter_mut().enumerate() {
        *slot ^= seed.wrapping_mul((c * 8 + w) as u32);
      }
    }
  }
  s
}

#[cfg(feature = "simd")]
#[rstest]
#[case::iv(0)]
#[case::mixed(0xdeadbeef)]
fn permute(#[case] seed: u32) {
  let mut s = make_state(seed);
  let mut t = s;
  scalar::p5(&mut s);
  simd::permute_state(&mut t);
  assert_eq!(s, t, "luffa permute diverged");
}

#[cfg(feature = "simd")]
#[rstest]
#[case::zeros([0u32; 8])]
#[case::pattern([1, 2, 3, 4, 5, 6, 7, 8])]
fn inject_message(#[case] msg: [u32; 8]) {
  let mut s = IV;
  let mut t = IV;
  scalar::mi5(&mut s, &msg);
  simd::inject_message(&mut t, &msg);
  assert_eq!(s, t, "luffa inject_message diverged");
}

#[cfg(feature = "simd")]
#[test]
fn inject_then_permute() {
  let mut s = IV;
  let mut t = IV;
  let msg = [0xABu32, 0xCD, 0xEF, 0x12, 0x34, 0x56, 0x78, 0x9A];
  scalar::mi5(&mut s, &msg);
  scalar::p5(&mut s);
  simd::inject_message(&mut t, &msg);
  simd::permute_state(&mut t);
  assert_eq!(s, t, "luffa inject+permute diverged");
}

mod kat {
  use super::common;

  use dash_pow::luffa::scalar;
  #[cfg(feature = "simd")]
  use dash_pow::luffa::simd;

  #[test]
  fn scalar_nist_kat() {
    let vectors = common::load("luffa");
    common::run_nist_kat("luffa/scalar", &vectors, scalar::hash512);
  }

  #[cfg(feature = "simd")]
  #[test]
  fn simd_nist_kat() {
    let vectors = common::load("luffa");
    common::run_nist_kat("luffa/simd", &vectors, simd::hash512);
  }
}
