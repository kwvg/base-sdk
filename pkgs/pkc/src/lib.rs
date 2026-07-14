//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Public-key cryptography for Dash.

#![no_std]

extern crate alloc;
#[cfg(feature = "std")]
extern crate std;

#[allow(unused_imports, reason = "ergonomic shim, exports may be unused")]
mod prelude;

cfg_if::cfg_if! {
  if #[cfg(feature = "test")] {
    #[doc(hidden)]
    pub mod tests;
  } else if #[cfg(test)] {
    mod tests;
  }
}

#[cfg(feature = "bls")]
pub mod bls;
pub mod ecdsa;
#[cfg(feature = "std")]
pub mod worker;
