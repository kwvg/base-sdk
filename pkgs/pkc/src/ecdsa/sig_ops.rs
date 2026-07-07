//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! secp256k1 signature.

use super::error::EcdsaError;
use super::EcdsaSigBytes;

use dash_types::type_cvrt;
use k256::ecdsa::{DerSignature, RecoveryId, Signature};

use core::hash::{Hash, Hasher};

/// An ECDSA signature (64-byte compact r||s).
#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
#[cfg_attr(
  feature = "serde",
  serde(into = "super::EcdsaSigBytes", try_from = "super::EcdsaSigBytes",)
)]
pub struct EcdsaSignature(Signature);

impl EcdsaSignature {
  pub(super) fn from_inner(inner: Signature) -> Self {
    Self(inner)
  }

  pub(super) fn as_inner(&self) -> &Signature {
    &self.0
  }

  /// Parse from 64-byte compact format (r || s).
  pub fn from_compact(bytes: &[u8; 64]) -> Result<Self, EcdsaError> {
    Signature::from_slice(bytes)
      .map(Self)
      .map_err(|_| EcdsaError::InvalidSignature)
  }

  /// Parse from DER-encoded bytes.
  pub fn from_der(bytes: &[u8]) -> Result<Self, EcdsaError> {
    Signature::from_der(bytes)
      .map(Self)
      .map_err(|_| EcdsaError::InvalidSignature)
  }

  /// Serialize as 64-byte compact format (r || s).
  pub fn to_compact(&self) -> [u8; 64] {
    self.0.to_bytes().into()
  }

  /// Encode as DER.
  pub fn to_der(&self) -> EcdsaDerSignature {
    EcdsaDerSignature(self.0.to_der())
  }
}

impl Hash for EcdsaSignature {
  fn hash<H: Hasher>(&self, state: &mut H) {
    self.to_compact().hash(state);
  }
}

type_cvrt!(From<EcdsaSignature> for EcdsaSigBytes, |sig| {
  Self(sig.to_compact())
});

type_cvrt!(TryFrom<EcdsaSigBytes> for EcdsaSignature, EcdsaError, |bytes| {
  Self::from_compact(&bytes.0)
});

/// Recovery id (0..3) used to recover a public key from an ECDSA
/// signature.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(into = "u8", try_from = "u8"))]
pub struct EcdsaRecoveryId(RecoveryId);

impl EcdsaRecoveryId {
  pub(super) fn from_inner(inner: RecoveryId) -> Self {
    Self(inner)
  }

  pub(super) fn as_inner(&self) -> RecoveryId {
    self.0
  }

  /// Create from a raw byte (0, 1, 2, or 3).
  pub fn new(id: u8) -> Result<Self, EcdsaError> {
    RecoveryId::try_from(id)
      .map(Self)
      .map_err(|_| EcdsaError::InvalidRecoveryId)
  }

  /// Return the raw byte value.
  pub fn to_byte(self) -> u8 {
    self.0.to_byte()
  }
}

type_cvrt!(From<EcdsaRecoveryId> for u8, |rid| {
  rid.to_byte()
});

type_cvrt!(TryFrom<u8> for EcdsaRecoveryId, EcdsaError, |byte| {
  Self::new(*byte)
});

/// DER-encoded ECDSA signature (variable length, typically 70-72 bytes).
#[derive(Clone, Debug)]
pub struct EcdsaDerSignature(DerSignature);

impl EcdsaDerSignature {
  /// Raw DER bytes.
  pub fn as_bytes(&self) -> &[u8] {
    self.0.as_bytes()
  }

  /// Byte length.
  pub fn len(&self) -> usize {
    self.0.as_bytes().len()
  }

  /// Whether the DER encoding is empty (always false for valid signatures).
  pub fn is_empty(&self) -> bool {
    self.0.as_bytes().is_empty()
  }
}

impl Eq for EcdsaDerSignature {}

impl PartialEq for EcdsaDerSignature {
  fn eq(&self, other: &Self) -> bool {
    self.as_bytes() == other.as_bytes()
  }
}
