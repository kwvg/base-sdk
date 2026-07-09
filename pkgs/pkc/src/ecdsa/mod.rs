//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! ECDSA types for the secp256k1 curve.

mod error;
mod public_bytes;
mod secret_bytes;
mod sig_bytes;

pub use error::EcdsaError;
pub use public_bytes::{EcdsaPkBytes, ECDSA_PK_LEN};
pub use secret_bytes::{EcdsaSkBytes, ECDSA_SK_LEN};
pub use sig_bytes::EcdsaSigBytes;

cfg_if::cfg_if! {
  if #[cfg(feature = "k256")] {
    mod public_ops;
    mod secret_ops;
    mod sig_ops;
    #[cfg(test)]
    #[expect(clippy::unwrap_used, reason = "test code")]
    mod tests;

    pub use public_ops::EcdsaPublicKey;
    pub use secret_ops::EcdsaSecretKey;
    pub use sig_ops::{EcdsaDerSignature, EcdsaSignature, EcdsaRecoveryId};
  }
}
