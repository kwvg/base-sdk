//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Error types for secp256k1 operations.

use core::fmt;

/// Errors produced by secp256k1 operations.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EcdsaError {
  /// compact signature header byte is not a valid flag
  InvalidCompactFlags,
  /// public key bytes are not a valid curve point
  InvalidPublicKey,
  /// recovery id is out of range (must be 0..4)
  InvalidRecoveryId,
  /// secret key bytes are not a valid scalar
  InvalidSecretKey,
  /// signature bytes are malformed
  InvalidSignature,
  /// DER-encoded private key has invalid structure
  MalformedDer,
  /// recovery failed; no valid public key for this signature and message
  RecoveryFailed,
  /// signing operation failed
  SigningFailed,
  /// signature verification failed
  VerifyFailed,
}

impl fmt::Display for EcdsaError {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    match self {
      Self::InvalidCompactFlags => {
        write!(f, "compact signature header byte is not a valid flag")
      }
      Self::InvalidPublicKey => {
        write!(f, "public key bytes are not a valid curve point")
      }
      Self::InvalidRecoveryId => {
        write!(f, "recovery id out of range (must be 0..4)")
      }
      Self::InvalidSecretKey => {
        write!(f, "secret key bytes are not a valid scalar")
      }
      Self::InvalidSignature => {
        write!(f, "signature bytes are malformed")
      }
      Self::MalformedDer => {
        write!(f, "DER-encoded private key has invalid structure")
      }
      Self::RecoveryFailed => {
        write!(f, "recovery failed; no valid public key")
      }
      Self::SigningFailed => write!(f, "signing failed"),
      Self::VerifyFailed => {
        write!(f, "signature verification failed")
      }
    }
  }
}

#[cfg(feature = "std")]
impl std::error::Error for EcdsaError {}
