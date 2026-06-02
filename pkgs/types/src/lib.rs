//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Shared types and macros for the Dash SDK.

#![no_std]

extern crate alloc;
#[cfg(feature = "std")]
extern crate std;

mod hex;
#[allow(unused_imports, reason = "ergonomic shim, exports may be unused")]
mod prelude;
mod uint;

#[doc(hidden)]
pub mod __private {
  pub use crate::hex::{ByteTypeDecoder, ByteTypeDecoderError};
  pub use bitcoin_consensus_encoding;
}

/// Helpers for `#[serde(with = "...")]` annotations.
#[cfg(feature = "serde")]
pub mod serialize {
  pub use crate::hex::serde as hex;
  pub use crate::uint::serde as uint;
}

pub use uint::{AsUint, TryFromUint};

make_bytes! {
  /// Platform node identifier for Evo masternodes.
  PlatformNodeId, 20, "crate::serialize::hex::w20"
}

make_bytes! {
  /// Raw BLS public key bytes (48 bytes, unvalidated).
  BlsPublicKeyBytes, 48, "crate::serialize::hex::w48"
}

make_bytes! {
  /// Raw BLS signature bytes (96 bytes, unvalidated).
  BlsSignatureBytes, 96, "crate::serialize::hex::w96"
}

make_bytes! {
  /// Raw compressed ECDSA public key bytes (33 bytes, unvalidated).
  EcdsaPublicKeyBytes, 33, "crate::serialize::hex::w33"
}

make_bytes! {
  /// Raw compact ECDSA signature bytes (64 bytes, unvalidated).
  EcdsaSignatureBytes, 64, "crate::serialize::hex::w64"
}
