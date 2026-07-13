//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Scheme-generic BLS secret key.

use super::error::BlsError;
use super::public_ops::BlsPublicKey;
use super::scheme_ops::BlsScheme;
use super::sig_basic::BlsSignature;
use super::{BlsSchemeId, BlsSigId};

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

  /// Sign a message using the default scheme.
  pub fn sign(&self, msg: &[u8]) -> BlsSignature<S> {
    BlsSignature(S::sign(&self.0, msg))
  }

  /// Sign with a specific scheme variant.
  ///
  /// # Errors
  ///
  /// Returns `UnsupportedScheme` for Chia (which has no DST
  /// mechanism).
  pub fn sign_with(&self, msg: &[u8], scheme: BlsSigId) -> Result<BlsSignature<S>, BlsError> {
    S::sign_with(&self.0, msg, scheme).map(BlsSignature)
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

#[cfg(test)]
mod tests {
  use super::*;
  use crate::bls::tests::{self, decode_hex, VectorFile, SEED_0};
  use crate::bls::{BlsScChia, BlsScIetf};

  use alloc::{string::String, vec::Vec};
  use hex_conservative::DisplayHex;
  use serde::Deserialize;

  #[derive(Deserialize)]
  struct KeygenVector {
    sk: String,
    pk: String,
  }

  fn assert_roundtrip<S: BlsSchemeId + BlsScheme>() {
    let sk = BlsSecretKey::<S>::generate(&SEED_0).unwrap();
    let restored = BlsSecretKey::<S>::from_bytes(&sk.to_bytes()).unwrap();
    assert_eq!(restored.public_key(), sk.public_key());
  }

  fn assert_derive_pk<S: BlsSchemeId + BlsScheme>(corpus: &str) {
    let f: VectorFile = tests::load(corpus);
    let vecs: Vec<KeygenVector> = tests::parse_sub(&f, "derive_pk");

    for v in &vecs {
      let sk_bytes: [u8; 32] = decode_hex(&v.sk).try_into().unwrap();
      let sk = BlsSecretKey::<S>::from_bytes(&sk_bytes).unwrap();
      assert_eq!(sk.public_key().to_bytes().to_lower_hex_string(), v.pk);
    }
  }

  #[test]
  fn derive_public_key_matches_vectors() {
    assert_derive_pk::<BlsScChia>("bls_chia_keygen");
    assert_derive_pk::<BlsScIetf>("bls_ietf_keygen");
  }

  #[test]
  fn generate_rejects_short_ikm() {
    assert!(BlsSecretKey::<BlsScChia>::generate(&[0u8; 31]).is_err());
    assert!(BlsSecretKey::<BlsScIetf>::generate(&[0u8; 31]).is_err());
  }

  #[test]
  fn public_key_formats_differ() {
    let chia = BlsSecretKey::<BlsScChia>::generate(&SEED_0).unwrap();
    let ietf = BlsSecretKey::<BlsScIetf>::from_bytes(&chia.to_bytes()).unwrap();
    assert_ne!(chia.public_key().to_bytes(), ietf.public_key().to_bytes());
  }

  #[test]
  fn serialization_roundtrip() {
    assert_roundtrip::<BlsScChia>();
    assert_roundtrip::<BlsScIetf>();
  }
}
