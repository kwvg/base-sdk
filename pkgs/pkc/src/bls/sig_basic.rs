//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Scheme-generic BLS signature.

use super::error::BlsError;
use super::public_ops::BlsPublicKey;
use super::scheme_ops::BlsScheme;
use super::{BlsSchemeId, BlsSigId};

use core::fmt;
use core::hash;

/// A BLS signature (96-byte compressed G2 point), generic over
/// the scheme.
pub struct BlsSignature<S: BlsSchemeId + BlsScheme>(pub(crate) S::InnerSig);

impl<S: BlsSchemeId + BlsScheme> BlsSignature<S> {
  /// Deserialize from 96 bytes.
  pub fn from_bytes(bytes: &[u8; 96]) -> Result<Self, BlsError> {
    S::sig_from_bytes(bytes).map(Self)
  }

  /// Serialize to 96 bytes.
  pub fn to_bytes(&self) -> [u8; 96] {
    S::sig_to_bytes(&self.0)
  }

  /// Verify with the default scheme.
  pub fn verify(&self, msg: &[u8], pk: &BlsPublicKey<S>) -> Result<(), BlsError> {
    S::verify(&self.0, msg, &pk.0)
  }

  /// Verify with a specific scheme variant.
  ///
  /// # Errors
  ///
  /// Returns `UnsupportedScheme` for Chia.
  pub fn verify_with(&self, msg: &[u8], pk: &BlsPublicKey<S>, scheme: BlsSigId) -> Result<(), BlsError> {
    S::verify_with(&self.0, msg, &pk.0, scheme)
  }

  pub(crate) fn from_inner(inner: S::InnerSig) -> Self {
    Self(inner)
  }
}

impl<S: BlsSchemeId + BlsScheme> Clone for BlsSignature<S> {
  fn clone(&self) -> Self {
    Self(self.0.clone())
  }
}

impl<S: BlsSchemeId + BlsScheme> fmt::Debug for BlsSignature<S> {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    self.0.fmt(f)
  }
}

impl<S: BlsSchemeId + BlsScheme> PartialEq for BlsSignature<S> {
  fn eq(&self, other: &Self) -> bool {
    self.0 == other.0
  }
}

impl<S: BlsSchemeId + BlsScheme> Eq for BlsSignature<S> {}

impl<S: BlsSchemeId + BlsScheme> hash::Hash for BlsSignature<S> {
  fn hash<H: hash::Hasher>(&self, state: &mut H) {
    self.to_bytes().hash(state);
  }
}

#[cfg(feature = "serde")]
impl<S: BlsSchemeId + BlsScheme> serde::Serialize for BlsSignature<S> {
  fn serialize<Ser: serde::Serializer>(&self, serializer: Ser) -> Result<Ser::Ok, Ser::Error> {
    let bytes = crate::bls::BlsSigBytes::<S>::from_bytes(self.to_bytes());
    bytes.serialize(serializer)
  }
}

#[cfg(feature = "serde")]
impl<'de, S: BlsSchemeId + BlsScheme> serde::Deserialize<'de> for BlsSignature<S> {
  fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
    let bytes = crate::bls::BlsSigBytes::<S>::deserialize(deserializer)?;
    Self::from_bytes(bytes.as_bytes()).map_err(serde::de::Error::custom)
  }
}

impl<S: BlsSchemeId + BlsScheme> From<BlsSignature<S>> for crate::bls::BlsSigBytes<S> {
  fn from(sig: BlsSignature<S>) -> Self {
    Self::from_bytes(sig.to_bytes())
  }
}

impl<S: BlsSchemeId + BlsScheme> TryFrom<crate::bls::BlsSigBytes<S>> for BlsSignature<S> {
  type Error = BlsError;

  fn try_from(bytes: crate::bls::BlsSigBytes<S>) -> Result<Self, Self::Error> {
    Self::from_bytes(bytes.as_bytes())
  }
}
