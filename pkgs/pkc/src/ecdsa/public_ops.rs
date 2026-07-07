//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! secp256k1 public key.

use super::error::EcdsaError;
use super::sig_ops::{EcdsaRecoveryId, EcdsaSignature};
use super::EcdsaPkBytes;

use dash_types::type_cvrt;
use k256::ecdsa::{signature::hazmat::PrehashVerifier, VerifyingKey};

use core::hash::{Hash, Hasher};

/// A secp256k1 public key.
#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
#[cfg_attr(
  feature = "serde",
  serde(into = "super::EcdsaPkBytes", try_from = "super::EcdsaPkBytes",)
)]
pub struct EcdsaPublicKey(VerifyingKey);

impl EcdsaPublicKey {
  pub(super) fn from_inner(inner: VerifyingKey) -> Self {
    Self(inner)
  }

  /// Parse from SEC1 (un)compressed bytes.
  pub fn from_bytes(bytes: &[u8]) -> Result<Self, EcdsaError> {
    VerifyingKey::from_sec1_bytes(bytes)
      .map(Self)
      .map_err(|_| EcdsaError::InvalidPublicKey)
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

  /// Verify a signature over a 32-byte prehashed message.
  pub fn verify(&self, msg_hash: &[u8; 32], sig: &EcdsaSignature) -> Result<(), EcdsaError> {
    self
      .0
      .verify_prehash(msg_hash, sig.as_inner())
      .map_err(|_| EcdsaError::VerifyFailed)
  }

  /// Recover a public key from a signature, prehashed message, and recovery id.
  pub fn recover(msg_hash: &[u8; 32], sig: &EcdsaSignature, rid: EcdsaRecoveryId) -> Result<Self, EcdsaError> {
    VerifyingKey::recover_from_prehash(msg_hash, sig.as_inner(), rid.as_inner())
      .map(Self)
      .map_err(|_| EcdsaError::RecoveryFailed)
  }
}

impl Hash for EcdsaPublicKey {
  fn hash<H: Hasher>(&self, state: &mut H) {
    self.to_bytes().hash(state);
  }
}

type_cvrt!(From<EcdsaPublicKey> for EcdsaPkBytes, |pk| {
  Self(pk.to_bytes())
});

type_cvrt!(TryFrom<EcdsaPkBytes> for EcdsaPublicKey, EcdsaError, |bytes| {
  Self::from_bytes(&bytes.0)
});
