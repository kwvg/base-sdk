//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! BMW-512 tests.

#![expect(clippy::panic, reason = "test code")]

mod common;

#[cfg(all(feature = "_internal", feature = "simd"))]
use dash_pow::bmw::{consts::IV, scalar, simd};
#[cfg(all(feature = "_internal", feature = "simd"))]
use rstest::rstest;

/// Loads a 128-byte block as sixteen little-endian u64 words.
#[cfg(all(feature = "_internal", feature = "simd"))]
fn bytes_to_words(block: &[u8; 128]) -> [u64; 16] {
  core::array::from_fn(|i| {
    let off = i * 8;
    u64::from_le_bytes([
      block[off],
      block[off + 1],
      block[off + 2],
      block[off + 3],
      block[off + 4],
      block[off + 5],
      block[off + 6],
      block[off + 7],
    ])
  })
}

/// Creates a 128-byte block filled with a running pattern.
#[cfg(all(feature = "_internal", feature = "simd"))]
fn make_block(fill: u8) -> [u8; 128] {
  let mut b = [0u8; 128];
  for (i, slot) in b.iter_mut().enumerate() {
    *slot = fill.wrapping_add(i as u8);
  }
  b
}

#[cfg(all(feature = "_internal", feature = "simd"))]
#[rstest]
#[case::zeros([0u8; 128])]
#[case::pattern(make_block(0x13))]
#[case::high(make_block(0xA7))]
fn compress(#[case] block: [u8; 128]) {
  let words = bytes_to_words(&block);
  let mut out_scalar = [0u64; 16];
  let mut out_simd = [0u64; 16];
  scalar::compress(&block, &IV, &mut out_scalar);
  simd::compress(&words, &IV, &mut out_simd);
  assert_eq!(out_scalar, out_simd, "bmw compress diverged");
}

#[cfg(all(feature = "_internal", feature = "simd"))]
#[test]
fn bytes_to_words_round_trip() {
  let block = make_block(0x42);
  let words = bytes_to_words(&block);
  let mut reconstructed = [0u8; 128];
  for (i, &w) in words.iter().enumerate() {
    reconstructed[i * 8..(i + 1) * 8].copy_from_slice(&w.to_le_bytes());
  }
  assert_eq!(block, reconstructed);
}

#[cfg(feature = "_internal")]
mod kat {
  use crate::common;

  use dash_pow::bmw::scalar;
  #[cfg(feature = "simd")]
  use dash_pow::bmw::simd;

  #[test]
  fn nist_vectors_scalar() {
    let vectors = common::load("bmw");
    common::run_nist_kat("bmw/scalar", &vectors, scalar::hash512);
  }

  #[cfg(feature = "simd")]
  #[test]
  fn nist_vectors_simd() {
    let vectors = common::load("bmw");
    common::run_nist_kat("bmw/simd", &vectors, simd::hash512);
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
