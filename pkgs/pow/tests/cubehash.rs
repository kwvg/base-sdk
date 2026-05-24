//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! CubeHash-16/32-512 tests.

#![expect(clippy::panic, reason = "test code")]
#![cfg_attr(feature = "simd", feature(portable_simd))]

mod common;

#[cfg(all(feature = "_internal", feature = "simd"))]
use dash_pow::cubehash::{consts::IV, scalar, simd};
#[cfg(all(feature = "_internal", feature = "simd"))]
use rstest::rstest;

#[cfg(all(feature = "_internal", feature = "simd"))]
use core::simd::Simd;

/// Converts a flat `[u32; 32]` state into the SIMD `[Simd<u32, 4>; 8]` layout.
#[cfg(all(feature = "_internal", feature = "simd"))]
fn flat_to_vec(flat: &[u32; 32]) -> [Simd<u32, 4>; 8] {
  core::array::from_fn(|i| Simd::from_array([flat[i * 4], flat[i * 4 + 1], flat[i * 4 + 2], flat[i * 4 + 3]]))
}

/// Converts the SIMD `[Simd<u32, 4>; 8]` layout back to a flat `[u32; 32]`.
#[cfg(all(feature = "_internal", feature = "simd"))]
fn vec_to_flat(v: &[Simd<u32, 4>; 8]) -> [u32; 32] {
  let mut out = [0u32; 32];
  for (i, lane) in v.iter().enumerate() {
    let a = lane.to_array();
    out[i * 4..i * 4 + 4].copy_from_slice(&a);
  }
  out
}

#[cfg(all(feature = "_internal", feature = "simd"))]
#[test]
fn state_round_trip() {
  let orig = IV;
  assert_eq!(vec_to_flat(&flat_to_vec(&orig)), orig);
}

#[cfg(all(feature = "_internal", feature = "simd"))]
#[rstest]
#[case::iv(IV)]
#[case::mixed({
  let mut s = IV;
  for (i, slot) in s.iter_mut().enumerate() { *slot ^= 0xdeadbeef_u32.wrapping_mul(i as u32); }
  s
})]
fn sixteen_rounds(#[case] init: [u32; 32]) {
  let mut s = init;
  let mut t = flat_to_vec(&init);
  scalar::sixteen_rounds(&mut s);
  simd::sixteen_rounds(&mut t);
  assert_eq!(s, vec_to_flat(&t), "cubehash sixteen_rounds diverged");
}

#[cfg(all(feature = "_internal", feature = "simd"))]
#[test]
fn absorb_block_agree() {
  let block = [0xABu8; 32];
  let mut s_scalar = IV;
  let mut s_simd = flat_to_vec(&IV);
  scalar::absorb_block(&mut s_scalar, &block);

  let lo = simd::load_vec(&IV, 0);
  let hi = simd::load_vec(&IV, 1);
  let lo = lo
    ^ Simd::from_array([
      u32::from_le_bytes([block[0], block[1], block[2], block[3]]),
      u32::from_le_bytes([block[4], block[5], block[6], block[7]]),
      u32::from_le_bytes([block[8], block[9], block[10], block[11]]),
      u32::from_le_bytes([block[12], block[13], block[14], block[15]]),
    ]);
  let hi = hi
    ^ Simd::from_array([
      u32::from_le_bytes([block[16], block[17], block[18], block[19]]),
      u32::from_le_bytes([block[20], block[21], block[22], block[23]]),
      u32::from_le_bytes([block[24], block[25], block[26], block[27]]),
      u32::from_le_bytes([block[28], block[29], block[30], block[31]]),
    ]);
  s_simd[0] = lo;
  s_simd[1] = hi;
  simd::sixteen_rounds(&mut s_simd);

  assert_eq!(s_scalar, vec_to_flat(&s_simd), "cubehash absorb_block diverged");
}

#[cfg(feature = "_internal")]
mod kat {
  use crate::common;

  use dash_pow::cubehash::scalar;
  #[cfg(feature = "simd")]
  use dash_pow::cubehash::simd;

  #[test]
  fn nist_vectors_scalar() {
    let vectors = common::load("cubehash");
    common::run_nist_kat("cubehash/scalar", &vectors, scalar::hash512);
  }

  #[cfg(feature = "simd")]
  #[test]
  fn nist_vectors_simd() {
    let vectors = common::load("cubehash");
    common::run_nist_kat("cubehash/simd", &vectors, simd::hash512);
  }

  #[cfg(feature = "simd")]
  #[test]
  fn scalar_simd_agree_on_empty() {
    assert_eq!(scalar::hash512(b""), simd::hash512(b""));
  }

  #[cfg(feature = "simd")]
  #[test]
  fn scalar_simd_agree_on_short() {
    let msg = b"dash";
    assert_eq!(scalar::hash512(msg), simd::hash512(msg));
  }
}
