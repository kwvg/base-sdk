//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Keccak-512 hash function.

pub mod consts;
pub_if_internal! { mod scalar; }
#[cfg(feature = "simd")]
pub_if_internal! { mod simd; }

cfg_if::cfg_if! {
  if #[cfg(feature = "simd")] {
    pub use simd::hash512;
  } else {
    pub use scalar::hash512;
  }
}

/// Keccak-512 sponge parameterised over a permutation function.
#[cfg(feature = "simd")]
pub(crate) fn sponge(data: &[u8], perm: fn(&mut [u64; 25])) -> dash_num::Hash512 {
  use crate::util::memops::{load_u64_le, store_u64_le};

  use consts::RATE;

  let mut state = [0u64; 25];
  let mut pos = 0;
  while pos + RATE <= data.len() {
    let mut i = 0;
    while i < 9 {
      state[i] ^= load_u64_le(&data[pos..], i);
      i += 1;
    }
    perm(&mut state);
    pos += RATE;
  }

  let mut last = [0u8; RATE];
  let remaining = data.len() - pos;
  last[..remaining].copy_from_slice(&data[pos..]);
  last[remaining] = 0x01;
  last[RATE - 1] |= 0x80;
  let mut i = 0;
  while i < 9 {
    state[i] ^= load_u64_le(&last, i);
    i += 1;
  }
  perm(&mut state);

  let mut out = [0u8; 64];
  let mut i = 0;
  while i < 8 {
    store_u64_le(&mut out, i, state[i]);
    i += 1;
  }
  dash_num::Hash512::from(out)
}
