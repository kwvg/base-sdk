//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Proof-of-work hash used by Dash.
//!
//! Chains eleven 512-bit hash algorithms (Blake, BMW, Groestl, Skein, JH,
//! Keccak, Luffa, CubeHash, SHAvite, SIMD, Echo) and truncates the final output
//! to 256 bits.

#![no_std]
#![cfg_attr(feature = "simd", feature(portable_simd))]

extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

#[allow(unused_imports, reason = "ergonomic shim, exports may be unused")]
mod prelude;
mod util;

use dash_num::Hash256;

#[cfg(feature = "std")]
pub mod worker;

/// Makes items `pub` when the `_internal` feature is active, otherwise keeps
/// them crate-private. Used to expose scalar reference implementations and SIMD
/// internals for testing.
macro_rules! pub_if_internal {
  ($(mod $name:ident;)+) => {
    $(
      #[cfg(feature = "_internal")]
      pub mod $name;
      #[cfg(not(feature = "_internal"))]
      mod $name;
    )+
  };
  (#[allow(dead_code)] $(mod $name:ident;)+) => {
    $(
      #[cfg(feature = "_internal")]
      #[allow(dead_code, reason = "const evaluation and test validation only")]
      pub mod $name;
      #[cfg(not(feature = "_internal"))]
      #[allow(dead_code, reason = "const evaluation and test validation only")]
      mod $name;
    )+
  };
}

pub_if_internal! {
  mod blake;
  mod bmw;
  mod cubehash;
  mod echo;
  mod groestl;
  mod jh;
  mod keccak;
  mod luffa;
  mod shavite;
  mod simd_hash;
  mod skein;
}

/// Computes the Dash proof-of-work hash.
pub fn hash(data: &[u8]) -> Hash256 {
  let h = blake::hash512(data);
  let h = bmw::hash512(h.as_ref());
  let h = groestl::hash512(h.as_ref());
  let h = skein::hash512(h.as_ref());
  let h = jh::hash512(h.as_ref());
  let h = keccak::hash512(h.as_ref());
  let h = luffa::hash512(h.as_ref());
  let h = cubehash::hash512(h.as_ref());
  let h = shavite::hash512(h.as_ref());
  let h = simd_hash::hash512(h.as_ref());
  let h = echo::hash512(h.as_ref());
  let mut out = [0u8; 32];
  out.copy_from_slice(&h.as_bytes()[..32]);
  Hash256::from(out)
}
