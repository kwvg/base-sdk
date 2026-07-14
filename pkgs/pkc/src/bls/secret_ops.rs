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
use crate::prelude::*;

use zeroize::Zeroizing;

use core::fmt::{Debug, Formatter, Result as FmtResult};

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
  /// Returns `InvalidKeyMaterial` when `ikm` is shorter than 32
  /// bytes.
  pub fn generate(ikm: &[u8]) -> Result<Self, BlsError> {
    S::generate(ikm).map(Self)
  }

  /// Parse from a 32-byte big-endian scalar.
  pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self, BlsError> {
    S::sk_from_bytes(bytes).map(Self)
  }

  /// Serialize to 32 bytes; the buffer is zeroised on drop.
  pub fn to_bytes(&self) -> Zeroizing<[u8; 32]> {
    Zeroizing::new(S::sk_to_bytes(&self.0))
  }

  /// Derive the corresponding public key.
  pub fn public_key(&self) -> BlsPublicKey<S> {
    BlsPublicKey(S::derive_pk(&self.0))
  }

  /// Sign a message using the default scheme.
  ///
  /// # Errors
  ///
  /// Returns `InvalidMessageLength` for Chia when `msg` is not
  /// exactly 32 bytes.
  pub fn sign(&self, msg: &[u8]) -> Result<BlsSignature<S>, BlsError> {
    S::sign(&self.0, msg).map(BlsSignature)
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

  /// Sum multiple secret keys (mod group order).
  pub fn aggregate(keys: &[&Self]) -> Result<Self, BlsError> {
    let inner_refs: Vec<&S::InnerSk> = keys.iter().map(|k| &k.0).collect();
    S::aggregate_sk(&inner_refs).map(Self::from_inner)
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

impl<S: BlsSchemeId + BlsScheme> Debug for BlsSecretKey<S> {
  fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
    write!(f, "BlsSecretKey<{}>(..)", S::LABEL)
  }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "test code")]
mod tests {
  use super::*;
  use crate::bls::tests::{assert_short_ikm_rejected, assert_sk_roundtrip};
  use crate::bls::{BlsScChia, BlsScIetf};
  use crate::tests::SEED_0;

  use dash_dev::{bls_keygen, load_corpus_json};
  use hex_literal::hex;
  use rstest::rstest;

  /// BLS12-381 scalar field order r, big-endian.
  const GROUP_ORDER: [u8; 32] = hex!(
    "73eda753299d7d483339d80809a1d805"
    "53bda402fffe5bfeffffffff00000001"
  );

  fn assert_derive_pk<S: BlsSchemeId + BlsScheme>(corpus: &str) {
    let corpus = load_corpus_json(env!("CARGO_MANIFEST_DIR"), corpus);
    let vecs = bls_keygen(&corpus, "derive_pk");

    for v in &vecs {
      let sk = BlsSecretKey::<S>::from_bytes(&v.sk).unwrap();
      assert_eq!(sk.public_key().to_bytes(), v.pk);
    }
  }

  #[rstest]
  #[case::chia(assert_derive_pk::<BlsScChia>, "bls_chia_keygen")]
  #[case::ietf(assert_derive_pk::<BlsScIetf>, "bls_ietf_keygen")]
  fn derive_public_key_matches_vectors(#[case] assertion: fn(&str), #[case] corpus: &str) {
    assertion(corpus);
  }

  #[rstest]
  #[case::chia(assert_short_ikm_rejected::<BlsScChia>)]
  #[case::ietf(assert_short_ikm_rejected::<BlsScIetf>)]
  fn generate_rejects_short_ikm(#[case] assertion: fn()) {
    assertion();
  }

  fn assert_sk_scalar_range<S: BlsSchemeId + BlsScheme>() {
    let zero = [0u8; 32];
    assert!(BlsSecretKey::<S>::from_bytes(&zero).is_err());
    assert!(BlsSecretKey::<S>::from_bytes(&GROUP_ORDER).is_err());
    assert!(BlsSecretKey::<S>::from_bytes(&[0xffu8; 32]).is_err());

    let mut one = [0u8; 32];
    one[31] = 1;
    assert!(BlsSecretKey::<S>::from_bytes(&one).is_ok());

    let mut order_minus_one = GROUP_ORDER;
    order_minus_one[31] = 0;
    assert!(BlsSecretKey::<S>::from_bytes(&order_minus_one).is_ok());
  }

  #[rstest]
  #[case::chia(assert_sk_scalar_range::<BlsScChia>)]
  #[case::ietf(assert_sk_scalar_range::<BlsScIetf>)]
  fn rejects_out_of_range_scalars(#[case] assertion: fn()) {
    assertion();
  }

  fn assert_sk_modulus_neighbourhood<S: BlsSchemeId + BlsScheme>() {
    // Ported from bls-signatures 0.15.0 key.rs test_from_bytes
    // (there in little-endian repr): the smallest integer greater
    // than the modulus must be rejected while simple small
    // scalars parse.
    let mut order_plus_one = GROUP_ORDER;
    order_plus_one[31] = 2;
    assert!(BlsSecretKey::<S>::from_bytes(&order_plus_one).is_err());

    for small in [10u8, 100] {
      let mut bytes = [0u8; 32];
      bytes[31] = small;
      assert!(BlsSecretKey::<S>::from_bytes(&bytes).is_ok());
    }
  }

  #[rstest]
  #[case::chia(assert_sk_modulus_neighbourhood::<BlsScChia>)]
  #[case::ietf(assert_sk_modulus_neighbourhood::<BlsScIetf>)]
  fn rejects_scalars_just_past_the_modulus(#[case] assertion: fn()) {
    assertion();
  }

  fn assert_corrupted_first_byte_rejected<S: BlsSchemeId + BlsScheme>() {
    // dashbls test.cpp "Should throw on a bad private key":
    // overwriting the first byte of a valid key with 255 pushes
    // the scalar past the group order.
    let sk = BlsSecretKey::<S>::generate(&SEED_0).unwrap();
    let mut bytes = *sk.to_bytes();
    bytes[0] = 255;
    assert!(BlsSecretKey::<S>::from_bytes(&bytes).is_err());
  }

  #[rstest]
  #[case::chia(assert_corrupted_first_byte_rejected::<BlsScChia>)]
  #[case::ietf(assert_corrupted_first_byte_rejected::<BlsScIetf>)]
  fn rejects_corrupted_first_byte(#[case] assertion: fn()) {
    assertion();
  }

  #[rstest]
  fn public_key_formats_differ() {
    let chia = BlsSecretKey::<BlsScChia>::generate(&SEED_0).unwrap();
    let ietf = BlsSecretKey::<BlsScIetf>::from_bytes(&chia.to_bytes()).unwrap();
    assert_ne!(chia.public_key().to_bytes(), ietf.public_key().to_bytes());
  }

  #[rstest]
  #[case::chia(assert_sk_roundtrip::<BlsScChia>)]
  #[case::ietf(assert_sk_roundtrip::<BlsScIetf>)]
  fn serialization_roundtrip(#[case] assertion: fn()) {
    assertion();
  }
}
