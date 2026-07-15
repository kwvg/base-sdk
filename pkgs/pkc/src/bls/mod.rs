//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! BLS12-381 types with type-level scheme discrimination.

use cfg_if::cfg_if;

mod error;
mod ies_bytes;
mod public_bytes;
mod schemes;
mod secret_bytes;
mod share_bytes;
mod sig_bytes;
#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "test code")]
mod tests;

pub use error::BlsError;
pub use ies_bytes::{BlsIesBytes, BlsIesMultiBytes, BLS_IES_IV_LEN};
pub use public_bytes::{BlsPkBytes, BLS_PK_LEN};
pub use schemes::{BlsScChia, BlsScIetf, BlsSchemeId};
pub use secret_bytes::{BlsSkBytes, BLS_SK_LEN};
pub use share_bytes::{BlsPkShareBytes, BlsSigShareBytes, BlsSkShareBytes};
pub use sig_bytes::{BlsSigBytes, BLS_SIG_LEN};

cfg_if! {
  if #[cfg(feature = "bls")] {
    #[expect(unsafe_code, reason = "blst C FFI")]
    mod blst_ffi;
    mod chia_h2c;
    mod ies_ops;
    mod lagrange;
    mod msg_point;
    mod public_ops;
    mod scheme_chia;
    mod scheme_ietf;
    mod scheme_ops;
    mod secret_ops;
    mod share_ops;
    mod sig_aggregate;
    mod sig_basic;
    mod sig_ops;
    mod sig_pop;
    mod sig_threshold;
    mod vvec_ops;

    #[cfg(feature = "test")]
    #[doc(hidden)]
    pub use scheme_ops::BlsScheme;
    pub use public_ops::BlsPublicKey;
    pub use secret_ops::BlsSecretKey;
    pub use share_ops::{BlsPkShare, BlsSigShare, BlsSkShare};
    pub use vvec_ops::BlsVerificationVector;
    pub use lagrange::BlsLagrangeCoefficients;
    pub use msg_point::BlsMessagePoint;
    pub use sig_basic::BlsSignature;
    pub use sig_ops::BlsSigId;
  }
}
