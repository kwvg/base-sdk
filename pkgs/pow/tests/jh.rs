//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! JH-512 tests.

#![expect(clippy::unwrap_used, reason = "test code")]
#![expect(clippy::panic, reason = "test code")]

mod common;

#[cfg(all(feature = "_internal", feature = "simd"))]
use dash_pow::jh::{consts::IV, scalar, simd};
#[cfg(all(feature = "_internal", feature = "simd"))]
use rstest::rstest;

/// Converts a flat `[u64; 16]` scalar state to eight SIMD rows.
#[cfg(all(feature = "_internal", feature = "simd"))]
fn u64_to_rows(state: &[u64; 16]) -> [simd::Row; 8] {
  core::array::from_fn(|i| simd::row_from_u64_pair([state[i * 2], state[i * 2 + 1]]))
}

/// Converts eight SIMD rows back to a flat `[u64; 16]` scalar state.
#[cfg(all(feature = "_internal", feature = "simd"))]
fn rows_to_u64(rows: &[simd::Row; 8]) -> [u64; 16] {
  let mut out = [0u64; 16];
  for i in 0..8 {
    let p = simd::row_to_u64_pair(rows[i]);
    out[i * 2] = p[0];
    out[i * 2 + 1] = p[1];
  }
  out
}

/// Flattens the `[[u64; 2]; 8]` IV into a `[u64; 16]` state array.
#[cfg(all(feature = "_internal", feature = "simd"))]
fn flatten_iv() -> [u64; 16] {
  let mut h = [0u64; 16];
  for i in 0..8 {
    h[2 * i] = IV[i][0];
    h[2 * i + 1] = IV[i][1];
  }
  h
}

/// Decodes a 64-byte block as eight little-endian u64 words.
#[cfg(all(feature = "_internal", feature = "simd"))]
fn bytes_to_words(block: &[u8; 64]) -> [u64; 8] {
  core::array::from_fn(|i| {
    let off = i * 8;
    u64::from_le_bytes(block[off..off + 8].try_into().unwrap())
  })
}

#[cfg(all(feature = "_internal", feature = "simd"))]
#[test]
fn row_round_trip() {
  let scalar_iv = flatten_iv();
  assert_eq!(rows_to_u64(&u64_to_rows(&scalar_iv)), scalar_iv);
}

#[cfg(all(feature = "_internal", feature = "simd"))]
#[test]
fn row_round_trip_arbitrary() {
  let mut state = [0u64; 16];
  for (i, slot) in state.iter_mut().enumerate() {
    *slot = 0xdeadbeef_cafebabe_u64.wrapping_mul(i as u64 + 1);
  }
  assert_eq!(rows_to_u64(&u64_to_rows(&state)), state);
}

#[cfg(all(feature = "_internal", feature = "simd"))]
#[rstest]
#[case::zeros([0u8; 64])]
#[case::pattern({
  let mut b = [0u8; 64];
  for (i, slot) in b.iter_mut().enumerate() { *slot = (i as u8).wrapping_mul(11); }
  b
})]
#[case::high({
  let mut b = [0u8; 64];
  for (i, slot) in b.iter_mut().enumerate() { *slot = 0xFF - i as u8; }
  b
})]
fn compress(#[case] block: [u8; 64]) {
  let scalar_iv = flatten_iv();
  let words = bytes_to_words(&block);

  let mut h_scalar = scalar_iv;
  let mut h_simd = IV.map(simd::row_from_u64_pair);

  scalar::compress(&mut h_scalar, &block);
  simd::compress(&mut h_simd, &words);

  assert_eq!(h_scalar, rows_to_u64(&h_simd), "jh compress diverged");
}

#[cfg(all(feature = "_internal", feature = "simd"))]
#[test]
fn e8_agree() {
  let scalar_iv = flatten_iv();

  let mut h_scalar = scalar_iv;
  let mut h_simd = u64_to_rows(&scalar_iv);

  scalar::e8(&mut h_scalar);

  // The SIMD path doesn't expose e8 directly, but we can
  // compress a zero block and back out the XOR:
  // compress does: state ^= block[0..4], e8, state[4..8] ^= block[0..4]
  // With zero block, compress is just e8.
  let zero_words = [0u64; 8];
  simd::compress(&mut h_simd, &zero_words);

  assert_eq!(h_scalar, rows_to_u64(&h_simd), "jh e8 diverged");
}

#[cfg(feature = "_internal")]
mod kat {
  use crate::common;

  use dash_pow::jh::scalar;
  #[cfg(feature = "simd")]
  use dash_pow::jh::simd;

  #[test]
  fn nist_vectors_scalar() {
    let vectors = common::load("jh");
    common::run_nist_kat("jh/scalar", &vectors, scalar::hash512);
  }

  #[cfg(feature = "simd")]
  #[test]
  fn nist_vectors_simd() {
    let vectors = common::load("jh");
    common::run_nist_kat("jh/simd", &vectors, simd::hash512);
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
