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
    pub(crate) mod scheme_ops;

    mod scheme_chia;
    mod scheme_ietf;
    mod schemes;
    mod sig_ops;
    #[cfg(test)]
    #[allow(dead_code, reason = "temporary refactor artifact")]
    #[expect(clippy::unwrap_used, clippy::panic, reason = "test code")]
    mod tests;

    pub use schemes::{BlsScChia, BlsScIetf, BlsSchemeId};
    pub use sig_ops::BlsSigId;
  }
}
