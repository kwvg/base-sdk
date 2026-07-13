//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Unified BLS cryptography module.

mod error;
mod public_bytes;
mod schemes;
mod secret_bytes;
mod share_bytes;
mod sig_bytes;

pub use error::BlsError;
pub use public_bytes::{BlsPkBytes, BLS_PK_LEN};
pub use schemes::{BlsScChia, BlsScIetf, BlsSchemeId};
pub use secret_bytes::{BlsSkBytes, BLS_SK_LEN};
pub use share_bytes::{BlsSigShareBytes, BlsSkShareBytes};
pub use sig_bytes::{BlsSigBytes, BLS_SIG_LEN};

cfg_if::cfg_if! {
  if #[cfg(feature = "bls")] {
    #[expect(unsafe_code, reason = "blst C FFI")]
    pub(crate) mod blst_ffi;
    pub(crate) mod chia_h2c;
    pub(crate) mod scheme_ops;

    mod public_ops;
    mod scheme_chia;
    mod scheme_ietf;
    mod secret_ops;
    mod sig_aggregate;
    mod sig_basic;
    mod sig_ops;
    mod sig_pop;
    #[cfg(test)]
    #[allow(dead_code, reason = "temporary refactor artifact")]
    #[expect(clippy::unwrap_used, clippy::panic, reason = "test code")]
    mod tests;

    pub use public_ops::BlsPublicKey;
    pub use secret_ops::BlsSecretKey;
    pub use sig_basic::BlsSignature;
    pub use sig_ops::BlsSigId;
  }
}
