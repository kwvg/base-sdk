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

#[cfg(test)]
mod tests {
  use super::*;
  use crate::bls::secret_ops::BlsSecretKey;
  use crate::bls::{BlsScChia, BlsScIetf};
  use crate::tests::{self, decode_hex, VectorFile, MSG_DEADBEEF, SEED_0, SEED_1};

  use alloc::{string::String, vec::Vec};
  use hex_conservative::DisplayHex;
  use serde::Deserialize;

  #[derive(Deserialize)]
  struct SerInternalVector {
    sig_legacy: String,
    sig_ietf: String,
  }

  fn assert_signing<S: BlsSchemeId + BlsScheme>() {
    let sk0 = BlsSecretKey::<S>::generate(&SEED_0).unwrap();
    let sk1 = BlsSecretKey::<S>::generate(&SEED_1).unwrap();
    let sig = sk0.sign(&MSG_DEADBEEF);

    assert!(sig.verify(&MSG_DEADBEEF, &sk0.public_key()).is_ok());

    let mut wrong_msg = MSG_DEADBEEF;
    wrong_msg[0] ^= 0xff;
    assert!(sig.verify(&wrong_msg, &sk0.public_key()).is_err());
    assert!(sig.verify(&MSG_DEADBEEF, &sk1.public_key()).is_err());

    assert_eq!(sk0.sign(&MSG_DEADBEEF), sig);
    assert_eq!(BlsSignature::<S>::from_bytes(&sig.to_bytes()).unwrap(), sig);
  }

  #[test]
  fn serialization_formats_match_vectors() {
    let f: VectorFile = tests::load("bls_chia_ser_internals");
    let vecs: Vec<SerInternalVector> = tests::parse_sub(&f, "sig_serialization");

    for v in &vecs {
      let chia = BlsSignature::<BlsScChia>::from_bytes(&decode_hex(&v.sig_legacy).try_into().unwrap()).unwrap();
      assert_eq!(chia.to_bytes().to_lower_hex_string(), v.sig_legacy);

      let ietf = BlsSignature::<BlsScIetf>::from_bytes(&decode_hex(&v.sig_ietf).try_into().unwrap()).unwrap();
      assert_eq!(ietf.to_bytes().to_lower_hex_string(), v.sig_ietf);

      assert_ne!(v.sig_legacy, v.sig_ietf);
    }
  }

  #[cfg(feature = "serde")]
  #[test]
  fn serde_roundtrip() {
    let chia_sk = BlsSecretKey::<BlsScChia>::generate(&SEED_0).unwrap();
    let chia = chia_sk.sign(&MSG_DEADBEEF);
    let json = serde_json::to_string(&chia).unwrap();
    assert_eq!(serde_json::from_str::<BlsSignature<BlsScChia>>(&json).unwrap(), chia);

    let ietf_sk = BlsSecretKey::<BlsScIetf>::generate(&SEED_0).unwrap();
    let ietf = ietf_sk.sign(&MSG_DEADBEEF);
    let json = serde_json::to_string(&ietf).unwrap();
    assert_eq!(serde_json::from_str::<BlsSignature<BlsScIetf>>(&json).unwrap(), ietf);
  }

  #[test]
  fn signatures_differ_across_schemes() {
    let chia = BlsSecretKey::<BlsScChia>::generate(&SEED_0).unwrap();
    let ietf = BlsSecretKey::<BlsScIetf>::from_bytes(&chia.to_bytes()).unwrap();
    assert_ne!(chia.sign(&MSG_DEADBEEF).to_bytes(), ietf.sign(&MSG_DEADBEEF).to_bytes());
  }

  #[test]
  fn signing_roundtrip_and_rejections() {
    assert_signing::<BlsScChia>();
    assert_signing::<BlsScIetf>();
  }
}
