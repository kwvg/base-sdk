//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! secp256k1 public key.

use super::error::Error;
use super::sig::{RecoveryId, Signature};

use k256::ecdsa::{self, signature::hazmat::PrehashVerifier};

/// A secp256k1 public key.
#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(
  feature = "serde",
  serde(
    into = "dash_types::EcdsaPublicKeyBytes",
    try_from = "dash_types::EcdsaPublicKeyBytes",
  )
)]
pub struct PublicKey(ecdsa::VerifyingKey);

impl PublicKey {
  pub(super) fn from_inner(inner: ecdsa::VerifyingKey) -> Self {
    Self(inner)
  }

  /// Parse from SEC1 bytes: 33 (compressed) or 65 (uncompressed).
  pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
    ecdsa::VerifyingKey::from_sec1_bytes(bytes)
      .map(Self)
      .map_err(|_| Error::InvalidPublicKey)
  }

  /// Serialize as 33-byte compressed SEC1.
  pub fn to_bytes(&self) -> [u8; 33] {
    let pt = self.0.to_encoded_point(true);
    let mut out = [0u8; 33];
    out.copy_from_slice(pt.as_bytes());
    out
  }

  /// Serialize as 65-byte uncompressed SEC1.
  pub fn to_uncompressed_bytes(&self) -> [u8; 65] {
    let pt = self.0.to_encoded_point(false);
    let mut out = [0u8; 65];
    out.copy_from_slice(pt.as_bytes());
    out
  }

  /// Verify an ECDSA signature over a 32-byte prehashed message.
  pub fn verify(&self, msg_hash: &[u8; 32], sig: &Signature) -> Result<(), Error> {
    self
      .0
      .verify_prehash(msg_hash, sig.as_inner())
      .map_err(|_| Error::VerifyFailed)
  }

  /// Recover a public key from a signature, prehashed message, and recovery id.
  pub fn recover(msg_hash: &[u8; 32], sig: &Signature, rid: RecoveryId) -> Result<Self, Error> {
    ecdsa::VerifyingKey::recover_from_prehash(msg_hash, sig.as_inner(), rid.as_inner())
      .map(Self)
      .map_err(|_| Error::RecoveryFailed)
  }
}

impl core::hash::Hash for PublicKey {
  fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
    self.to_bytes().hash(state);
  }
}

impl From<PublicKey> for dash_types::EcdsaPublicKeyBytes {
  fn from(pk: PublicKey) -> Self {
    Self(pk.to_bytes())
  }
}

impl TryFrom<dash_types::EcdsaPublicKeyBytes> for PublicKey {
  type Error = super::error::Error;

  fn try_from(bytes: dash_types::EcdsaPublicKeyBytes) -> Result<Self, Self::Error> {
    Self::from_bytes(&bytes.0)
  }
}
