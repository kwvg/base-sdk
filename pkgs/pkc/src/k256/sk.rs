//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! secp256k1 secret key.

use super::error::Error;
use super::pk::PublicKey;
use super::sig::{RecoveryId, Signature};

use k256::ecdsa::{self, signature::hazmat::PrehashSigner};

use core::fmt;

/// A secp256k1 secret key (32-byte scalar).
#[derive(Clone)]
pub struct SecretKey(ecdsa::SigningKey);

impl SecretKey {
  /// Parse a secret key from a 32-byte big-endian scalar.
  pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self, Error> {
    ecdsa::SigningKey::from_bytes(bytes.into())
      .map(Self)
      .map_err(|_| Error::InvalidSecretKey)
  }

  /// Serialize to a 32-byte big-endian scalar.
  pub fn to_bytes(&self) -> [u8; 32] {
    self.0.to_bytes().into()
  }

  /// Derive the corresponding public key.
  pub fn public_key(&self) -> PublicKey {
    PublicKey::from_inner(*self.0.verifying_key())
  }

  /// Produce an ECDSA signature over a 32-byte prehashed message (RFC 6979,
  /// low-S normalised).
  ///
  /// # Errors
  ///
  /// Returns [`Error::SigningFailed`] if the underlying library rejects the
  /// prehash.
  pub fn sign(&self, msg_hash: &[u8; 32]) -> Result<Signature, Error> {
    self
      .0
      .sign_prehash(msg_hash)
      .map(Signature::from_inner)
      .map_err(|_| Error::SigningFailed)
  }

  /// Sign and return the recovery id needed to recover the public key from
  /// the signature.
  ///
  /// # Errors
  ///
  /// Returns [`Error::SigningFailed`] if the underlying library rejects the
  /// prehash.
  pub fn sign_recoverable(&self, msg_hash: &[u8; 32]) -> Result<(Signature, RecoveryId), Error> {
    self
      .0
      .sign_prehash(msg_hash)
      .map(|(sig, rid)| (Signature::from_inner(sig), RecoveryId::from_inner(rid)))
      .map_err(|_| Error::SigningFailed)
  }
}

impl fmt::Debug for SecretKey {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "SecretKey(..)")
  }
}
