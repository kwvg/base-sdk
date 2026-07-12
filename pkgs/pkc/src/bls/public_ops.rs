//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Scheme-generic BLS public key.

use super::error::BlsError;
use super::scheme_ops::BlsScheme;
use super::BlsSchemeId;

use core::fmt;
use core::hash;

/// A BLS public key (48-byte compressed G1 point), generic over
/// the scheme.
pub struct BlsPublicKey<S: BlsSchemeId + BlsScheme>(pub(crate) S::InnerPk);

impl<S: BlsSchemeId + BlsScheme> BlsPublicKey<S> {
  /// Deserialize from 48 bytes.
  pub fn from_bytes(bytes: &[u8; 48]) -> Result<Self, BlsError> {
    S::pk_from_bytes(bytes).map(Self)
  }

  /// Serialize to 48 bytes.
  pub fn to_bytes(&self) -> [u8; 48] {
    S::pk_to_bytes(&self.0)
  }

  pub(crate) fn from_inner(inner: S::InnerPk) -> Self {
    Self(inner)
  }
}

impl<S: BlsSchemeId + BlsScheme> Clone for BlsPublicKey<S> {
  fn clone(&self) -> Self {
    Self(self.0.clone())
  }
}

impl<S: BlsSchemeId + BlsScheme> fmt::Debug for BlsPublicKey<S> {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    self.0.fmt(f)
  }
}

impl<S: BlsSchemeId + BlsScheme> PartialEq for BlsPublicKey<S> {
  fn eq(&self, other: &Self) -> bool {
    self.0 == other.0
  }
}

impl<S: BlsSchemeId + BlsScheme> Eq for BlsPublicKey<S> {}

impl<S: BlsSchemeId + BlsScheme> hash::Hash for BlsPublicKey<S> {
  fn hash<H: hash::Hasher>(&self, state: &mut H) {
    self.to_bytes().hash(state);
  }
}

#[cfg(feature = "serde")]
impl<S: BlsSchemeId + BlsScheme> serde::Serialize for BlsPublicKey<S> {
  fn serialize<Ser: serde::Serializer>(&self, serializer: Ser) -> Result<Ser::Ok, Ser::Error> {
    let bytes = crate::bls::BlsPkBytes::<S>::from_bytes(self.to_bytes());
    bytes.serialize(serializer)
  }
}

#[cfg(feature = "serde")]
impl<'de, S: BlsSchemeId + BlsScheme> serde::Deserialize<'de> for BlsPublicKey<S> {
  fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
    let bytes = crate::bls::BlsPkBytes::<S>::deserialize(deserializer)?;
    Self::from_bytes(bytes.as_bytes()).map_err(serde::de::Error::custom)
  }
}

impl<S: BlsSchemeId + BlsScheme> From<BlsPublicKey<S>> for crate::bls::BlsPkBytes<S> {
  fn from(pk: BlsPublicKey<S>) -> Self {
    Self::from_bytes(pk.to_bytes())
  }
}

impl<S: BlsSchemeId + BlsScheme> TryFrom<crate::bls::BlsPkBytes<S>> for BlsPublicKey<S> {
  type Error = BlsError;

  fn try_from(bytes: crate::bls::BlsPkBytes<S>) -> Result<Self, Self::Error> {
    Self::from_bytes(bytes.as_bytes())
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::bls::tests::{self, decode_hex, VectorFile};
  use crate::bls::{BlsScChia, BlsScIetf};

  use alloc::{string::String, vec::Vec};
  use hex_conservative::DisplayHex;
  use serde::Deserialize;

  #[derive(Deserialize)]
  struct SerInternalVector {
    pk_legacy: String,
    pk_ietf: String,
  }

  #[test]
  fn serialization_formats_match_vectors() {
    let f: VectorFile = tests::load("bls_chia_ser_internals");
    let vecs: Vec<SerInternalVector> = tests::parse_sub(&f, "pk_serialization");

    for v in &vecs {
      let legacy_bytes: [u8; 48] = decode_hex(&v.pk_legacy).try_into().unwrap();
      let legacy = BlsPublicKey::<BlsScChia>::from_bytes(&legacy_bytes).unwrap();
      assert_eq!(legacy.to_bytes().to_lower_hex_string(), v.pk_legacy);

      let ietf_bytes: [u8; 48] = decode_hex(&v.pk_ietf).try_into().unwrap();
      let ietf = BlsPublicKey::<BlsScIetf>::from_bytes(&ietf_bytes).unwrap();
      assert_eq!(ietf.to_bytes().to_lower_hex_string(), v.pk_ietf);

      assert_ne!(v.pk_legacy, v.pk_ietf);
    }
  }

  #[cfg(feature = "serde")]
  #[test]
  fn serde_roundtrip() {
    let f: VectorFile = tests::load("bls_chia_ser_internals");
    let v: SerInternalVector = tests::parse_sub::<SerInternalVector>(&f, "pk_serialization")
      .into_iter()
      .next()
      .unwrap();

    let chia = BlsPublicKey::<BlsScChia>::from_bytes(&decode_hex(&v.pk_legacy).try_into().unwrap()).unwrap();
    let json = serde_json::to_string(&chia).unwrap();
    assert_eq!(serde_json::from_str::<BlsPublicKey<BlsScChia>>(&json).unwrap(), chia);

    let ietf = BlsPublicKey::<BlsScIetf>::from_bytes(&decode_hex(&v.pk_ietf).try_into().unwrap()).unwrap();
    let json = serde_json::to_string(&ietf).unwrap();
    assert_eq!(serde_json::from_str::<BlsPublicKey<BlsScIetf>>(&json).unwrap(), ietf);
  }
}
