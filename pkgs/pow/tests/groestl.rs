//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Groestl-512 tests.

#![expect(clippy::panic, reason = "test code")]
#![cfg_attr(feature = "simd", feature(portable_simd))]

mod common;

#[cfg(all(feature = "_internal", feature = "simd"))]
use dash_pow::groestl::{scalar, simd};
#[cfg(all(feature = "_internal", feature = "simd"))]
use rstest::rstest;

#[cfg(all(feature = "_internal", feature = "simd"))]
use core::simd::Simd;

/// Groestl-512 IV: all zeros except the last word encodes the output size.
#[cfg(all(feature = "_internal", feature = "simd"))]
fn groestl_iv() -> [u64; 16] {
  let mut h = [0u64; 16];
  let out = 512u64;
  h[15] = ((out & 0xFF) << 56) | ((out & 0xFF00) << 40);
  h
}

/// Groestl-512 IV unpacked into the row-wise layout used by the SIMD path.
#[cfg(all(feature = "_internal", feature = "simd"))]
fn groestl_iv_rows() -> [Simd<u8, 16>; 8] {
  let iv = groestl_iv();
  u64_state_to_rows(&iv)
}

/// Converts a `[u64; 16]` column-major state to eight rows of 16 bytes
/// using the same column-major to row-major transpose as `load_block`.
///
/// Byte `(row, col)` lives at offset `col * 8 + row` in the flat buffer,
/// and in `state[col]` at byte position `row`.
#[cfg(all(feature = "_internal", feature = "simd"))]
fn u64_state_to_rows(state: &[u64; 16]) -> [Simd<u8, 16>; 8] {
  core::array::from_fn(|row| {
    let mut bytes = [0u8; 16];
    for col in 0..16 {
      bytes[col] = (state[col] >> (row * 8)) as u8;
    }
    Simd::from_array(bytes)
  })
}

/// Converts eight row vectors back to a `[u64; 16]` column-major state.
#[cfg(all(feature = "_internal", feature = "simd"))]
fn rows_to_u64_state(rows: &[Simd<u8, 16>; 8]) -> [u64; 16] {
  let mut state = [0u64; 16];
  for (col, slot) in state.iter_mut().enumerate() {
    let mut word = 0u64;
    for (row, r) in rows.iter().enumerate() {
      word |= (r.as_array()[col] as u64) << (row * 8);
    }
    *slot = word;
  }
  state
}

#[cfg(all(feature = "_internal", feature = "simd"))]
#[test]
fn state_round_trip() {
  let orig = groestl_iv();
  assert_eq!(rows_to_u64_state(&u64_state_to_rows(&orig)), orig);
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
#[case::pattern(make_block(0x37))]
#[case::high(make_block(0xC1))]
fn compress(#[case] block: [u8; 128]) {
  let mut h_scalar = groestl_iv();
  scalar::compress(&mut h_scalar, &block);

  let mut h_simd = groestl_iv_rows();
  simd::compress_block(&mut h_simd, &block);

  let simd_as_u64 = rows_to_u64_state(&h_simd);
  assert_eq!(h_scalar, simd_as_u64, "groestl compress diverged");
}

#[cfg(all(feature = "_internal", feature = "simd"))]
#[test]
fn output_transform_agree() {
  // Start from a state produced by compressing one block.
  let block = make_block(0x55);
  let mut h_scalar = groestl_iv();
  scalar::compress(&mut h_scalar, &block);

  let mut h_simd = u64_state_to_rows(&h_scalar);

  scalar::output_transform(&mut h_scalar);
  simd::output_transform(&mut h_simd);

  // Compare the right-half extraction (the actual digest bytes).
  let mut out_scalar = [0u8; 64];
  for i in 0..8 {
    out_scalar[i * 8..(i + 1) * 8].copy_from_slice(&h_scalar[i + 8].to_le_bytes());
  }

  let mut out_simd = [0u8; 64];
  simd::extract_right_half(&h_simd, &mut out_simd);

  assert_eq!(out_scalar, out_simd, "groestl output_transform diverged");
}

#[cfg(feature = "_internal")]
mod kat {
  use crate::common;

  use dash_pow::groestl::scalar;
  #[cfg(feature = "simd")]
  use dash_pow::groestl::simd;

  #[test]
  fn nist_vectors_scalar() {
    let vectors = common::load("groestl");
    common::run_nist_kat("groestl/scalar", &vectors, scalar::hash512);
  }

  #[cfg(feature = "simd")]
  #[test]
  fn nist_vectors_simd() {
    let vectors = common::load("groestl");
    common::run_nist_kat("groestl/simd", &vectors, simd::hash512);
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
