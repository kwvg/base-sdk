//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Skein-512 tests.

#![expect(clippy::unwrap_used, reason = "test code")]
#![expect(clippy::panic, reason = "test code")]

mod common;

#[cfg(all(feature = "_internal", feature = "simd"))]
use dash_pow::skein::{consts::IV, scalar, simd};
#[cfg(all(feature = "_internal", feature = "simd"))]
use rstest::rstest;

/// Decodes a 64-byte block as eight little-endian u64 words.
#[cfg(all(feature = "_internal", feature = "simd"))]
fn bytes_to_words(block: &[u8; 64]) -> [u64; 8] {
  core::array::from_fn(|i| {
    let off = i * 8;
    u64::from_le_bytes(block[off..off + 8].try_into().unwrap())
  })
}

/// Creates a 64-byte block filled with a running pattern.
#[cfg(all(feature = "_internal", feature = "simd"))]
fn make_block(fill: u8) -> [u8; 64] {
  let mut b = [0u8; 64];
  for (i, slot) in b.iter_mut().enumerate() {
    *slot = fill.wrapping_add(i as u8);
  }
  b
}

#[cfg(all(feature = "_internal", feature = "simd"))]
const MSG: u64 = 48 << 1;
#[cfg(all(feature = "_internal", feature = "simd"))]
const FIRST: u64 = 1 << 7;
#[cfg(all(feature = "_internal", feature = "simd"))]
const FINAL: u64 = 1 << 8;

#[cfg(all(feature = "_internal", feature = "simd"))]
#[rstest]
#[case::zeros_single_block([0u8; 64], 0, 64, MSG + FIRST + FINAL, true, true)]
#[case::pattern_single_block(make_block(0x42), 0, 64, MSG + FIRST + FINAL, true, true)]
#[case::first_only([0u8; 64], 0, 64, MSG + FIRST, true, false)]
fn ubi(
  #[case] block: [u8; 64],
  #[case] bcount: u64,
  #[case] extra: usize,
  #[case] etype: u64,
  #[case] first: bool,
  #[case] final_block: bool,
) {
  let block_words = bytes_to_words(&block);

  let mut h_scalar = IV;
  let mut h_simd = IV;

  scalar::ubi(&mut h_scalar, &block, bcount, extra, etype);

  simd::ubi(
    &mut h_simd,
    &block_words,
    simd::UbiTweak {
      position: (bcount << 6).wrapping_add(extra as u64),
      kind: 48,
      first,
      final_block,
    },
  );

  assert_eq!(h_scalar, h_simd, "skein ubi diverged");
}

#[cfg(all(feature = "_internal", feature = "simd"))]
#[test]
fn output_block_agree() {
  // Process empty message through both paths, then compare the output-block step.
  let block = [0u8; 64];
  let block_words = bytes_to_words(&block);

  let mut h_scalar = IV;
  let mut h_simd = IV;

  // Single message block (empty padded)
  scalar::ubi(&mut h_scalar, &block, 0, 0, MSG + FIRST + FINAL);
  simd::ubi(
    &mut h_simd,
    &block_words,
    simd::UbiTweak {
      position: 0,
      kind: 48,
      first: true,
      final_block: true,
    },
  );
  assert_eq!(h_scalar, h_simd, "skein message ubi diverged");

  // Output block
  let out_block = [0u8; 64];
  const OUTPUT: u64 = 63 << 1;
  scalar::ubi(&mut h_scalar, &out_block, 0, 8, OUTPUT + FIRST + FINAL);
  simd::output_block(&mut h_simd);

  assert_eq!(h_scalar, h_simd, "skein output block diverged");
}

#[cfg(feature = "_internal")]
mod kat {
  use crate::common;

  use dash_pow::skein::scalar;
  #[cfg(feature = "simd")]
  use dash_pow::skein::simd;

  #[test]
  fn nist_vectors_scalar() {
    let vectors = common::load("skein");
    common::run_nist_kat("skein/scalar", &vectors, scalar::hash512);
  }

  #[cfg(feature = "simd")]
  #[test]
  fn nist_vectors_simd() {
    let vectors = common::load("skein");
    common::run_nist_kat("skein/simd", &vectors, simd::hash512);
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
