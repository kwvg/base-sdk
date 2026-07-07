//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! secp256k1 secret key.

use super::error::EcdsaError;
use super::public_ops::EcdsaPublicKey;
use super::sig_ops::{EcdsaRecoveryId, EcdsaSignature};

use k256::ecdsa::{signature::hazmat::PrehashSigner, SigningKey};

use core::fmt::{Debug, Formatter, Result as FmtResult};

/// A secp256k1 secret key.
#[derive(Clone)]
pub struct EcdsaSecretKey(SigningKey);

impl EcdsaSecretKey {
  /// Parse a secret key from a 32-byte big-endian scalar.
  pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self, EcdsaError> {
    SigningKey::from_bytes(bytes.into())
      .map(Self)
      .map_err(|_| EcdsaError::InvalidSecretKey)
  }

  /// Serialize to a 32-byte big-endian scalar.
  pub fn to_bytes(&self) -> [u8; 32] {
    self.0.to_bytes().into()
  }

  /// Derive the corresponding public key.
  pub fn public_key(&self) -> EcdsaPublicKey {
    EcdsaPublicKey::from_inner(*self.0.verifying_key())
  }

  /// Produce an ECDSA signature over a 32-byte prehashed message
  /// (RFC 6979, low-S normalised).
  ///
  /// # Errors
  ///
  /// Returns [`EcdsaError::SigningFailed`] if the underlying library
  /// rejects the prehash.
  pub fn sign(&self, msg_hash: &[u8; 32]) -> Result<EcdsaSignature, EcdsaError> {
    self
      .0
      .sign_prehash(msg_hash)
      .map(EcdsaSignature::from_inner)
      .map_err(|_| EcdsaError::SigningFailed)
  }

  /// Sign and return the recovery id needed to recover the public
  /// key from the signature.
  ///
  /// # Errors
  ///
  /// Returns [`EcdsaError::SigningFailed`] if the underlying library
  /// rejects the prehash.
  pub fn sign_recoverable(&self, msg_hash: &[u8; 32]) -> Result<(EcdsaSignature, EcdsaRecoveryId), EcdsaError> {
    self
      .0
      .sign_prehash(msg_hash)
      .map(|(sig, rid)| (EcdsaSignature::from_inner(sig), EcdsaRecoveryId::from_inner(rid)))
      .map_err(|_| EcdsaError::SigningFailed)
  }
}

impl Debug for EcdsaSecretKey {
  fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
    write!(f, "EcdsaSecretKey(..)")
  }
}
