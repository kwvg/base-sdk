//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Scheme-generic BLS signature.

use super::error::BlsError;
use super::public_ops::BlsPublicKey;
use super::scheme_ops::BlsScheme;
use super::{BlsSchemeId, BlsSigBytes, BlsSigId};

use cfg_if::cfg_if;
use dash_num::Hash256;
use dash_types::{dlgt_codec, type_cvrt};

use core::fmt::{Debug, Formatter, Result as FmtResult};
use core::hash::{Hash, Hasher};

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

impl<S: BlsSchemeId + BlsScheme> Debug for BlsSignature<S> {
  fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
    self.0.fmt(f)
  }
}

impl<S: BlsSchemeId + BlsScheme> PartialEq for BlsSignature<S> {
  fn eq(&self, other: &Self) -> bool {
    self.0 == other.0
  }
}

impl<S: BlsSchemeId + BlsScheme> Eq for BlsSignature<S> {}

impl<S: BlsSchemeId + BlsScheme> Hash for BlsSignature<S> {
  fn hash<H: Hasher>(&self, state: &mut H) {
    self.to_bytes().hash(state);
  }
}

cfg_if! {
  if #[cfg(feature = "serde")] {
    use serde::de::Error;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    impl<S: BlsSchemeId + BlsScheme> Serialize for BlsSignature<S> {
      fn serialize<Ser: Serializer>(&self, serializer: Ser) -> Result<Ser::Ok, Ser::Error> {
        let bytes = BlsSigBytes::<S>::from_bytes(self.to_bytes());
        bytes.serialize(serializer)
      }
    }

    impl<'de, S: BlsSchemeId + BlsScheme> Deserialize<'de> for BlsSignature<S> {
      fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let bytes = BlsSigBytes::<S>::deserialize(deserializer)?;
        Self::from_bytes(bytes.as_bytes()).map_err(Error::custom)
      }
    }
  }
}

dlgt_codec!(for[S: BlsSchemeId + BlsScheme] BlsSignature<S> => BlsSigBytes<S>, Hash256, BlsError);

type_cvrt!(for[S: BlsSchemeId + BlsScheme] From<BlsSignature<S>> for BlsSigBytes<S>, |sig| {
  Self::from_bytes(sig.to_bytes())
});

type_cvrt!(for[S: BlsSchemeId + BlsScheme] TryFrom<BlsSigBytes<S>> for BlsSignature<S>, BlsError, |bytes| {
  Self::from_bytes(bytes.as_bytes())
});

#[cfg(test)]
mod tests {
  use super::*;
  use crate::bls::secret_ops::BlsSecretKey;
  use crate::bls::tests::assert_signing_roundtrip;
  use crate::bls::{BlsScChia, BlsScIetf};
  use crate::tests::{MSG_DEADBEEF, SEED_0};

  use dash_dev::{bls_sig_serialization, load_corpus_json};
  use rstest::rstest;
  #[cfg(feature = "serde")]
  use serde_json::{from_str, to_string};

  #[rstest]
  fn serialization_formats_match_vectors() {
    let corpus = load_corpus_json(env!("CARGO_MANIFEST_DIR"), "bls_chia_ser_internals");
    let vecs = bls_sig_serialization(&corpus, "sig_serialization");

    for v in &vecs {
      let chia = BlsSignature::<BlsScChia>::from_bytes(&v.legacy).unwrap();
      assert_eq!(chia.to_bytes(), v.legacy);

      let ietf = BlsSignature::<BlsScIetf>::from_bytes(&v.ietf).unwrap();
      assert_eq!(ietf.to_bytes(), v.ietf);

      assert_ne!(v.legacy, v.ietf);
    }
  }

  #[cfg(feature = "serde")]
  #[rstest]
  fn serde_roundtrip() {
    let chia_sk = BlsSecretKey::<BlsScChia>::generate(&SEED_0).unwrap();
    let chia = chia_sk.sign(&MSG_DEADBEEF);
    let json = to_string(&chia).unwrap();
    assert_eq!(from_str::<BlsSignature<BlsScChia>>(&json).unwrap(), chia);

    let ietf_sk = BlsSecretKey::<BlsScIetf>::generate(&SEED_0).unwrap();
    let ietf = ietf_sk.sign(&MSG_DEADBEEF);
    let json = to_string(&ietf).unwrap();
    assert_eq!(from_str::<BlsSignature<BlsScIetf>>(&json).unwrap(), ietf);
  }

  #[rstest]
  fn signatures_differ_across_schemes() {
    let chia = BlsSecretKey::<BlsScChia>::generate(&SEED_0).unwrap();
    let ietf = BlsSecretKey::<BlsScIetf>::from_bytes(&chia.to_bytes()).unwrap();
    assert_ne!(chia.sign(&MSG_DEADBEEF).to_bytes(), ietf.sign(&MSG_DEADBEEF).to_bytes());
  }

  #[rstest]
  #[case::chia(assert_signing_roundtrip::<BlsScChia>)]
  #[case::ietf(assert_signing_roundtrip::<BlsScIetf>)]
  fn signing_roundtrip_and_rejections(#[case] assertion: fn()) {
    assertion();
  }
}
