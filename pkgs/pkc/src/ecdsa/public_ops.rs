//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! secp256k1 public key.

use super::error::EcdsaError;
use super::public_bytes::{EcdsaPkBytes, Sec1Byte};
use super::sig_ops::{EcdsaRecoveryId, EcdsaSignature};

use dash_num::Hash160;
use dash_types::{dlgt_codec, type_cvrt, TypeId};
use k256::ecdsa::{signature::hazmat::PrehashVerifier, VerifyingKey};

use core::hash::{Hash, Hasher};

/// A secp256k1 public key.
#[derive(Clone, Debug, Eq, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(into = "EcdsaPkBytes", try_from = "EcdsaPkBytes"))]
pub struct EcdsaPublicKey {
  inner: VerifyingKey,
  compressed: bool,
}

impl EcdsaPublicKey {
  pub(super) fn from_inner(inner: VerifyingKey, compressed: bool) -> Self {
    Self { inner, compressed }
  }

  /// Set the compression flag to uncompressed.
  pub fn decompress(&mut self) {
    self.compressed = false;
  }

  /// Parse from SEC1 (un)compressed bytes.
  pub fn from_bytes(bytes: &[u8]) -> Result<Self, EcdsaError> {
    let compressed = bytes
      .first()
      .and_then(|&b| Sec1Byte::from_base(b))
      .is_some_and(|s| s.is_compressed());
    VerifyingKey::from_sec1_bytes(bytes)
      .map(|key| Self { inner: key, compressed })
      .map_err(|_| EcdsaError::InvalidPublicKey)
  }

  /// Whether this key serializes as compressed.
  pub fn is_compressed(&self) -> bool {
    self.compressed
  }

  /// Serialize as 33-byte compressed SEC1.
  pub fn to_bytes(&self) -> [u8; 33] {
    let pt = self.inner.to_encoded_point(true);
    let mut out = [0u8; 33];
    out.copy_from_slice(pt.as_bytes());
    out
  }

  /// Serialize as 65-byte uncompressed SEC1.
  pub fn to_uncompressed_bytes(&self) -> [u8; 65] {
    let pt = self.inner.to_encoded_point(false);
    let mut out = [0u8; 65];
    out.copy_from_slice(pt.as_bytes());
    out
  }

  /// Recover a public key from a signature, prehashed message, and recovery id.
  pub fn recover(msg_hash: &[u8; 32], sig: &EcdsaSignature, rid: EcdsaRecoveryId) -> Result<Self, EcdsaError> {
    VerifyingKey::recover_from_prehash(msg_hash, sig.as_inner(), rid.as_inner())
      .map(|key| Self {
        inner: key,
        compressed: true,
      })
      .map_err(|_| EcdsaError::RecoveryFailed)
  }

  /// Verify a signature over a 32-byte prehashed message.
  pub fn verify(&self, msg_hash: &[u8; 32], sig: &EcdsaSignature) -> Result<(), EcdsaError> {
    self
      .inner
      .verify_prehash(msg_hash, sig.as_inner())
      .map_err(|_| EcdsaError::VerifyFailed)
  }
}

impl Hash for EcdsaPublicKey {
  fn hash<H: Hasher>(&self, state: &mut H) {
    self.to_bytes().hash(state);
  }
}

dlgt_codec!(EcdsaPublicKey => EcdsaPkBytes, Hash160, EcdsaError);

type_cvrt!(From<EcdsaPublicKey> for EcdsaPkBytes, |pk| {
  if pk.is_compressed() {
    Self::from_raw(&pk.to_bytes())
  } else {
    Self::from_raw(&pk.to_uncompressed_bytes())
  }
});

type_cvrt!(TryFrom<EcdsaPkBytes> for EcdsaPublicKey, EcdsaError, |bytes| {
  Self::from_bytes(bytes.as_bytes())
});

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "test code")]
mod tests {
  use crate::ecdsa::tests::*;
  use crate::ecdsa::{EcdsaPublicKey, EcdsaRecoveryId, EcdsaSecretKey, EcdsaSignature};

  use dash_dev::{ecdsa_recover, load_corpus_json};
  use rstest::*;

  #[rstest]
  fn compressed_roundtrip(alice_pk: EcdsaPublicKey) {
    let bytes = alice_pk.to_bytes();
    assert_eq!(bytes.len(), 33);
    let restored = EcdsaPublicKey::from_bytes(&bytes).unwrap();
    assert_eq!(restored, alice_pk);
  }

  #[rstest]
  fn corpus_recover() {
    let corpus = load_corpus_json(env!("CARGO_MANIFEST_DIR"), "k256_sign");
    for v in ecdsa_recover(&corpus, "recover") {
      let sig = EcdsaSignature::from_compact(&v.sig).unwrap();
      let rid = EcdsaRecoveryId::new(v.recovery_id).unwrap();
      let pk = EcdsaPublicKey::recover(&v.msg, &sig, rid).unwrap();
      assert_eq!(pk.to_bytes(), v.pk);
    }
  }

  #[rstest]
  fn rejects_garbage() {
    assert!(EcdsaPublicKey::from_bytes(&[0xff; 33]).is_err());
  }

  #[rstest]
  fn recover_roundtrip() {
    let sk = EcdsaSecretKey::from_bytes(&ALICE_SK).unwrap();
    let msg = [0xbb; 32];
    let (sig, rid) = sk.sign_recoverable(&msg).unwrap();
    let recovered = EcdsaPublicKey::recover(&msg, &sig, rid).unwrap();
    assert_eq!(recovered, sk.public_key());
  }

  #[cfg(feature = "serde")]
  #[rstest]
  fn serde_roundtrip(alice_pk: EcdsaPublicKey) {
    let json = serde_json::to_string(&alice_pk).unwrap();
    let restored: EcdsaPublicKey = serde_json::from_str(&json).unwrap();
    assert_eq!(restored, alice_pk);
  }

  #[rstest]
  fn uncompressed_roundtrip(alice_pk: EcdsaPublicKey) {
    let mut pk = alice_pk;
    pk.decompress();
    let bytes = pk.to_uncompressed_bytes();
    assert_eq!(bytes.len(), 65);
    let restored = EcdsaPublicKey::from_bytes(&bytes).unwrap();
    assert_eq!(restored, pk);
  }

  #[rstest]
  fn verify_rejects_wrong_message(alice_pk: EcdsaPublicKey) {
    let sk = EcdsaSecretKey::from_bytes(&ALICE_SK).unwrap();
    let msg = [0xaa; 32];
    let sig = sk.sign(&msg).unwrap();
    let mut bad = msg;
    bad[0] ^= 0xff;
    assert!(alice_pk.verify(&bad, &sig).is_err());
  }
}
