//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! ECDSA signature and recovery id.

use super::error::Error;

use k256::ecdsa;

/// An ECDSA signature (64-byte compact r||s).
#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
#[cfg_attr(
  feature = "serde",
  serde(
    into = "dash_types::EcdsaSignatureBytes",
    try_from = "dash_types::EcdsaSignatureBytes",
  )
)]
pub struct Signature(ecdsa::Signature);

impl Signature {
  pub(super) fn from_inner(inner: ecdsa::Signature) -> Self {
    Self(inner)
  }

  pub(super) fn as_inner(&self) -> &ecdsa::Signature {
    &self.0
  }

  /// Parse from 64-byte compact format (r || s).
  pub fn from_compact(bytes: &[u8; 64]) -> Result<Self, Error> {
    ecdsa::Signature::from_slice(bytes)
      .map(Self)
      .map_err(|_| Error::InvalidSignature)
  }

  /// Parse from DER-encoded bytes.
  pub fn from_der(bytes: &[u8]) -> Result<Self, Error> {
    ecdsa::Signature::from_der(bytes)
      .map(Self)
      .map_err(|_| Error::InvalidSignature)
  }

  /// Serialize as 64-byte compact format (r || s).
  pub fn to_compact(&self) -> [u8; 64] {
    self.0.to_bytes().into()
  }

  /// Encode as DER.
  pub fn to_der(&self) -> DerSignature {
    DerSignature(self.0.to_der())
  }
}

impl core::hash::Hash for Signature {
  fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
    self.to_compact().hash(state);
  }
}

impl From<Signature> for dash_types::EcdsaSignatureBytes {
  fn from(sig: Signature) -> Self {
    Self(sig.to_compact())
  }
}

impl TryFrom<dash_types::EcdsaSignatureBytes> for Signature {
  type Error = super::error::Error;

  fn try_from(bytes: dash_types::EcdsaSignatureBytes) -> Result<Self, Self::Error> {
    Self::from_compact(&bytes.0)
  }
}

/// Recovery id (0..3) used to recover a public key from an ECDSA signature.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(into = "u8", try_from = "u8"))]
pub struct RecoveryId(ecdsa::RecoveryId);

impl RecoveryId {
  pub(super) fn from_inner(inner: ecdsa::RecoveryId) -> Self {
    Self(inner)
  }

  pub(super) fn as_inner(&self) -> ecdsa::RecoveryId {
    self.0
  }

  /// Create from a raw byte (0, 1, 2, or 3).
  pub fn new(id: u8) -> Result<Self, Error> {
    ecdsa::RecoveryId::try_from(id)
      .map(Self)
      .map_err(|_| Error::InvalidRecoveryId)
  }

  /// Return the raw byte value.
  pub fn to_byte(self) -> u8 {
    self.0.to_byte()
  }
}

/// DER-encoded ECDSA signature (variable length, typically 70-72 bytes).
#[derive(Clone, Debug)]
pub struct DerSignature(ecdsa::DerSignature);

impl DerSignature {
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

impl PartialEq for DerSignature {
  fn eq(&self, other: &Self) -> bool {
    self.as_bytes() == other.as_bytes()
  }
}

impl Eq for DerSignature {}

impl From<RecoveryId> for u8 {
  fn from(rid: RecoveryId) -> Self {
    rid.to_byte()
  }
}

impl TryFrom<u8> for RecoveryId {
  type Error = super::error::Error;

  fn try_from(byte: u8) -> Result<Self, Self::Error> {
    Self::new(byte)
  }
}
