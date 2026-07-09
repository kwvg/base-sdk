//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! secp256k1 secret key.

use super::error::EcdsaError;
use super::public_ops::EcdsaPublicKey;
use super::secret_bytes::EcdsaSkBytes;
use super::sig_ops::{EcdsaRecoveryId, EcdsaSignature};

use dash_num::Hash256;
use dash_types::codec::{BaseCodec, DecodeError, EncodeBuf, Hashable};
use dash_types::{impl_type, type_cvrt, TypeId, MAX_SER_SIZE};
use k256::ecdsa::{signature::hazmat::PrehashSigner, SigningKey};
use k256::elliptic_curve::ops::Neg;
use rand_core::CryptoRngCore;

use core::fmt::{Debug, Formatter, Result as FmtResult};

/// A secp256k1 secret key.
#[derive(Clone, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(into = "EcdsaSkBytes", try_from = "EcdsaSkBytes"))]
pub struct EcdsaSecretKey {
  inner: SigningKey,
  compressed: bool,
}

impl EcdsaSecretKey {
  /// Parse a secret key from a 32-byte big-endian scalar.
  pub fn from_bytes(bytes: &[u8; 32], compressed: bool) -> Result<Self, EcdsaError> {
    SigningKey::from_bytes(bytes.into())
      .map(|key| Self { inner: key, compressed })
      .map_err(|_| EcdsaError::InvalidSecretKey)
  }

  /// Generate a new random secret key.
  pub fn generate(rng: &mut impl CryptoRngCore, compressed: bool) -> Self {
    Self {
      inner: SigningKey::random(rng),
      compressed,
    }
  }

  /// Whether the corresponding public key should be compressed.
  pub fn is_compressed(&self) -> bool {
    self.compressed
  }

  /// Negate the secret scalar in place.
  pub fn negate(&mut self) {
    let neg = self.inner.as_nonzero_scalar().neg();
    self.inner = SigningKey::from(neg);
  }

  /// Derive the corresponding public key.
  pub fn public_key(&self) -> EcdsaPublicKey {
    EcdsaPublicKey::from_inner(*self.inner.verifying_key(), self.compressed)
  }

  /// Serialize to a 32-byte big-endian scalar.
  pub fn to_bytes(&self) -> [u8; 32] {
    self.inner.to_bytes().into()
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
      .inner
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
      .inner
      .sign_prehash(msg_hash)
      .map(|(sig, rid)| (EcdsaSignature::from_inner(sig), EcdsaRecoveryId::from_inner(rid)))
      .map_err(|_| EcdsaError::SigningFailed)
  }

  /// Verify that a public key matches this secret key.
  pub fn verify_pubkey(&self, pubkey: &EcdsaPublicKey) -> bool {
    pubkey.is_compressed() == self.compressed && self.inner.verifying_key() == pubkey.as_inner()
  }
}

impl Debug for EcdsaSecretKey {
  fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
    write!(f, "EcdsaSecretKey(..)")
  }
}

impl Eq for EcdsaSecretKey {}

impl PartialEq for EcdsaSecretKey {
  fn eq(&self, other: &Self) -> bool {
    use subtle::ConstantTimeEq;
    self.to_bytes().ct_eq(&other.to_bytes()).into() && self.compressed == other.compressed
  }
}

impl BaseCodec<EcdsaError> for EcdsaSecretKey {
  fn decode(data: &mut &[u8]) -> Result<Self, DecodeError<EcdsaError>> {
    let inner = <EcdsaSkBytes as BaseCodec<EcdsaError>>::decode(data)?;
    Self::try_from(inner).map_err(DecodeError::DecError)
  }

  fn encode(&self, buf: &mut impl EncodeBuf) {
    EcdsaSkBytes::from(self.clone()).encode(buf);
  }
}

impl Hashable for EcdsaSecretKey {
  type Hash = Hash256;

  fn hash(&self) -> Hash256 {
    Hashable::hash(&EcdsaSkBytes::from(self.clone()))
  }
}

impl_type!(EcdsaSecretKey, MAX_SER_SIZE, EcdsaError);

type_cvrt!(From<EcdsaSecretKey> for EcdsaSkBytes, |sk| {
  Self::from_bytes(sk.to_bytes(), sk.is_compressed())
});

type_cvrt!(TryFrom<EcdsaSkBytes> for EcdsaSecretKey, EcdsaError, |bytes| {
  Self::from_bytes(bytes.as_bytes(), bytes.is_compressed())
});

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "test code")]
mod tests {
  use crate::ecdsa::tests::*;
  use crate::ecdsa::{EcdsaPublicKey, EcdsaSecretKey};

  use dash_dev::{ecdsa_keygen, ecdsa_sign, load_corpus_json};
  use hex_literal::hex;
  use rstest::*;

  #[rstest]
  fn corpus_derive_pk() {
    let corpus = load_corpus_json(env!("CARGO_MANIFEST_DIR"), "k256_keygen");
    for v in ecdsa_keygen(&corpus, "derive_pk") {
      let sk = EcdsaSecretKey::from_bytes(&v.sk, true).unwrap();
      assert_eq!(sk.public_key().to_bytes(), v.pk_compressed);
    }
  }

  #[rstest]
  fn corpus_sign_recoverable() {
    let corpus = load_corpus_json(env!("CARGO_MANIFEST_DIR"), "k256_sign");
    for v in ecdsa_sign(&corpus, "sign_recoverable") {
      let sk = EcdsaSecretKey::from_bytes(&v.sk, true).unwrap();
      let (sig, rid) = sk.sign_recoverable(&v.msg).unwrap();
      assert_eq!(sig.to_compact(), v.sig);
      assert_eq!(rid.to_byte(), v.recovery_id);
    }
  }

  #[rstest]
  fn from_bytes_roundtrip(alice_sk: EcdsaSecretKey) {
    let bytes = alice_sk.to_bytes();
    let restored = EcdsaSecretKey::from_bytes(&bytes, true).unwrap();
    assert_eq!(restored.public_key().to_bytes(), alice_sk.public_key().to_bytes());
  }

  #[rstest]
  fn negate_changes_key(alice_sk: EcdsaSecretKey) {
    let original_bytes = alice_sk.to_bytes();
    let mut negated = alice_sk.clone();
    negated.negate();
    assert_ne!(negated.to_bytes(), original_bytes);
    negated.negate();
    assert_eq!(negated.to_bytes(), original_bytes);
  }

  #[rstest]
  fn rejects_zero() {
    assert!(EcdsaSecretKey::from_bytes(&[0u8; 32], true).is_err());
  }

  #[rstest]
  fn sign_is_deterministic(alice_sk: EcdsaSecretKey) {
    let sig1 = alice_sk.sign(&MSG).unwrap();
    let sig2 = alice_sk.sign(&MSG).unwrap();
    assert_eq!(sig1, sig2);
  }

  #[rstest]
  fn sign_recoverable_roundtrip(alice_sk: EcdsaSecretKey) {
    let (sig, rid) = alice_sk.sign_recoverable(&MSG).unwrap();
    let recovered = EcdsaPublicKey::recover(&MSG, &sig, rid).unwrap();
    assert_eq!(recovered, alice_sk.public_key());
  }

  #[rstest]
  fn sign_verify_roundtrip(alice_sk: EcdsaSecretKey) {
    let sig = alice_sk.sign(&MSG).unwrap();
    assert!(alice_sk.public_key().verify(&MSG, &sig).is_ok());
  }

  #[cfg(feature = "serde")]
  #[rstest]
  fn serde_roundtrip(alice_sk: EcdsaSecretKey) {
    let json = serde_json::to_string(&alice_sk).unwrap();
    let restored: EcdsaSecretKey = serde_json::from_str(&json).unwrap();
    assert_eq!(restored.to_bytes(), alice_sk.to_bytes());
  }

  #[rstest]
  fn verify_pubkey_matches(alice_sk: EcdsaSecretKey) {
    assert!(alice_sk.verify_pubkey(&alice_sk.public_key()));
  }

  #[rstest]
  fn verify_rejects_wrong_key(alice_sk: EcdsaSecretKey) {
    let bob = EcdsaSecretKey::from_bytes(
      &hex!("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
      true,
    )
    .unwrap();
    assert!(!alice_sk.verify_pubkey(&bob.public_key()));
    let sig = alice_sk.sign(&MSG).unwrap();
    assert!(bob.public_key().verify(&MSG, &sig).is_err());
  }
}
