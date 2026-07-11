//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Unified BLS cryptography module.

mod error;

pub use error::BlsError;

cfg_if::cfg_if! {
  if #[cfg(feature = "bls")] {
    #[expect(unsafe_code, reason = "blst C FFI")]
    pub(crate) mod blst_ffi;
    pub(crate) mod chia_h2c;
  }
}
