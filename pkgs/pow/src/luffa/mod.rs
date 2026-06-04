//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Luffa-512 hash function.

#[cfg(not(feature = "_internal"))]
pub(crate) mod consts;

#[cfg(feature = "_internal")]
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
