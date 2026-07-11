//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Scheme-generic BLS secret key.

use super::error::BlsError;
use super::public_ops::BlsPublicKey;
use super::scheme_ops::BlsScheme;
use super::BlsSchemeId;

use core::fmt;

/// A BLS secret key (32-byte scalar), generic over the scheme.
///
/// Zeroised on drop.
pub struct BlsSecretKey<S: BlsSchemeId + BlsScheme>(pub(crate) S::InnerSk);

impl<S: BlsSchemeId + BlsScheme> Clone for BlsSecretKey<S> {
  fn clone(&self) -> Self {
    Self(self.0.clone())
  }
}

impl<S: BlsSchemeId + BlsScheme> BlsSecretKey<S> {
  /// Derive a secret key from input keying material (>= 32 bytes).
  ///
  /// # Errors
  ///
  /// Returns `InvalidKeyMaterial` or `InvalidSecretKey` when `ikm`
  /// is shorter than 32 bytes.
  pub fn generate(ikm: &[u8]) -> Result<Self, BlsError> {
    S::generate(ikm).map(Self)
  }

  /// Parse from a 32-byte big-endian scalar.
  pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self, BlsError> {
    S::sk_from_bytes(bytes).map(Self)
  }

  /// Serialize to 32 bytes.
  pub fn to_bytes(&self) -> [u8; 32] {
    S::sk_to_bytes(&self.0)
  }

  /// Derive the corresponding public key.
  pub fn public_key(&self) -> BlsPublicKey<S> {
    BlsPublicKey(S::derive_pk(&self.0))
  }

  pub(crate) fn from_inner(inner: S::InnerSk) -> Self {
    Self(inner)
  }
}

impl<S: BlsSchemeId + BlsScheme> Drop for BlsSecretKey<S> {
  fn drop(&mut self) {
    S::zeroize_sk(&mut self.0);
  }
}

impl<S: BlsSchemeId + BlsScheme> fmt::Debug for BlsSecretKey<S> {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "BlsSecretKey<{}>(..)", S::LABEL)
  }
}
