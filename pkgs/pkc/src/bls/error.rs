//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Error type for BLS operations.

use core::fmt::{Display, Formatter, Result as FmtResult};
#[cfg(feature = "std")]
use std::error::Error;

/// Errors produced by BLS operations.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BlsError {
  /// input keying material is too short (need >= 32 bytes)
  InvalidKeyMaterial,
  /// secret key bytes are not a valid scalar
  InvalidSecretKey,
  /// public key bytes are not a valid G1 point
  InvalidPublicKey,
  /// signature bytes are not a valid G2 point
  InvalidSignature,
  /// signature verification failed
  VerifyFailed,
  /// no items provided for aggregation
  EmptyAggregation,
  /// public key and message counts do not match
  CountMismatch,
  /// threshold exceeds total or is zero
  ThresholdTooLarge,
  /// not enough shares to recover
  InsufficientShares,
  /// duplicate share id in recovery set
  DuplicateShareId,
  /// plaintext length is not a multiple of 16
  InvalidPlaintextLength,
  /// AES decryption failed
  DecryptionFailed,
  /// recipient index out of range
  IndexOutOfRange,
  /// operation not supported for this scheme
  UnsupportedScheme,
}

impl Display for BlsError {
  fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
    match self {
      Self::InvalidKeyMaterial => write!(f, "input keying material too short"),
      Self::InvalidSecretKey => write!(f, "invalid secret key bytes"),
      Self::InvalidPublicKey => write!(f, "invalid public key bytes"),
      Self::InvalidSignature => write!(f, "invalid signature bytes"),
      Self::VerifyFailed => write!(f, "signature verification failed"),
      Self::EmptyAggregation => write!(f, "no items provided for aggregation"),
      Self::CountMismatch => write!(f, "public key and message counts differ"),
      Self::ThresholdTooLarge => write!(f, "threshold exceeds total or is zero"),
      Self::InsufficientShares => write!(f, "not enough shares to recover"),
      Self::DuplicateShareId => write!(f, "duplicate share id in recovery set"),
      Self::InvalidPlaintextLength => write!(f, "plaintext length is not a multiple of 16"),
      Self::DecryptionFailed => write!(f, "AES decryption failed"),
      Self::IndexOutOfRange => write!(f, "recipient index out of range"),
      Self::UnsupportedScheme => write!(f, "operation not supported for this scheme"),
    }
  }
}

#[cfg(feature = "std")]
impl Error for BlsError {}
