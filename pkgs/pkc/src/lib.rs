//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Public-key cryptography for Dash.

#![no_std]

extern crate alloc;

#[allow(unused_imports, reason = "ergonomic shim, exports may be unused")]
mod prelude;

pub mod ecdsa;

cfg_if::cfg_if! {
  if #[cfg(feature = "bls")] {
    #[expect(private_bounds, reason = "BlsScheme is crate-private")]
    pub mod bls;
    pub mod bls_chia;
    pub mod bls_ietf;
    mod common;
  }
}

cfg_if::cfg_if! {
  if #[cfg(feature = "std")] {
    extern crate std;

    pub mod worker;
  }
}

dash_types::make_bytes! {
  /// Raw BLS signature bytes (96 bytes, unvalidated).
  BlsSignatureBytes, 96
}
