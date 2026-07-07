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

#[cfg(any(feature = "bls_ietf", feature = "bls_chia"))]
mod common;
#[allow(unused_imports, reason = "ergonomic shim, exports may be unused")]
mod prelude;

#[cfg(feature = "bls_chia")]
pub mod bls_chia;
#[cfg(feature = "bls_ietf")]
pub mod bls_ietf;
pub mod ecdsa;
#[cfg(feature = "std")]
pub mod worker;

dash_types::make_bytes! {
  /// Raw BLS public key bytes (48 bytes, unvalidated).
  BlsPublicKeyBytes, 48
}

dash_types::make_bytes! {
  /// Raw BLS signature bytes (96 bytes, unvalidated).
  BlsSignatureBytes, 96
}
