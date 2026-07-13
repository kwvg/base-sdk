//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Scheme-generic BLS public key.

use super::error::BlsError;
use super::scheme_ops::BlsScheme;
use super::secret_ops::BlsSecretKey;
use super::{BlsPkBytes, BlsSchemeId};
use crate::prelude::*;

use cfg_if::cfg_if;
use dash_num::Hash160;
use dash_types::{dlgt_codec, type_cvrt};

use core::fmt::{Debug, Formatter, Result as FmtResult};
use core::hash::{Hash, Hasher};

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

  /// Compute a DH shared key: `sk * peer_pk`.
  pub fn dh_exchange(sk: &BlsSecretKey<S>, peer_pk: &Self) -> Result<Self, BlsError> {
    S::dh_exchange(&sk.0, &peer_pk.0).map(Self)
  }

  /// Aggregate multiple public keys into one.
  pub fn aggregate(keys: &[&Self]) -> Result<Self, BlsError> {
    let inner_refs: Vec<&S::InnerPk> = keys.iter().map(|k| &k.0).collect();
    S::aggregate_pk(&inner_refs).map(Self::from_inner)
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

impl<S: BlsSchemeId + BlsScheme> Debug for BlsPublicKey<S> {
  fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
    self.0.fmt(f)
  }
}

impl<S: BlsSchemeId + BlsScheme> PartialEq for BlsPublicKey<S> {
  fn eq(&self, other: &Self) -> bool {
    self.0 == other.0
  }
}

impl<S: BlsSchemeId + BlsScheme> Eq for BlsPublicKey<S> {}

impl<S: BlsSchemeId + BlsScheme> Hash for BlsPublicKey<S> {
  fn hash<H: Hasher>(&self, state: &mut H) {
    self.to_bytes().hash(state);
  }
}

cfg_if! {
  if #[cfg(feature = "serde")] {
    use serde::de::Error;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    impl<S: BlsSchemeId + BlsScheme> Serialize for BlsPublicKey<S> {
      fn serialize<Ser: Serializer>(&self, serializer: Ser) -> Result<Ser::Ok, Ser::Error> {
        let bytes = BlsPkBytes::<S>::from_bytes(self.to_bytes());
        bytes.serialize(serializer)
      }
    }

    impl<'de, S: BlsSchemeId + BlsScheme> Deserialize<'de> for BlsPublicKey<S> {
      fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let bytes = BlsPkBytes::<S>::deserialize(deserializer)?;
        Self::from_bytes(bytes.as_bytes()).map_err(Error::custom)
      }
    }
  }
}

dlgt_codec!(for[S: BlsSchemeId + BlsScheme] BlsPublicKey<S> => BlsPkBytes<S>, Hash160, BlsError);

type_cvrt!(for[S: BlsSchemeId + BlsScheme] From<BlsPublicKey<S>> for BlsPkBytes<S>, |pk| {
  Self::from_bytes(pk.to_bytes())
});

type_cvrt!(for[S: BlsSchemeId + BlsScheme] TryFrom<BlsPkBytes<S>> for BlsPublicKey<S>, BlsError, |bytes| {
  Self::from_bytes(bytes.as_bytes())
});

#[cfg(test)]
mod tests {
  use super::*;
  use crate::bls::{BlsScChia, BlsScIetf, BlsSecretKey};
  use crate::tests::{SEED_0, SEED_1};

  use dash_dev::{bls_pk_serialization, load_corpus_json};
  #[cfg(feature = "serde")]
  use serde_json::{from_str, to_string};

  fn assert_dh_roundtrip<S: BlsSchemeId + BlsScheme>() {
    let sk0 = BlsSecretKey::<S>::generate(&SEED_0).unwrap();
    let sk1 = BlsSecretKey::<S>::generate(&SEED_1).unwrap();
    let shared0 = BlsPublicKey::dh_exchange(&sk0, &sk1.public_key()).unwrap();
    let shared1 = BlsPublicKey::dh_exchange(&sk1, &sk0.public_key()).unwrap();
    assert_eq!(shared0, shared1);
  }

  #[test]
  fn dh_exchange_roundtrip() {
    assert_dh_roundtrip::<BlsScChia>();
    assert_dh_roundtrip::<BlsScIetf>();
  }

  #[test]
  fn serialization_formats_match_vectors() {
    let corpus = load_corpus_json(env!("CARGO_MANIFEST_DIR"), "bls_chia_ser_internals");
    let vecs = bls_pk_serialization(&corpus, "pk_serialization");

    for v in &vecs {
      let legacy = BlsPublicKey::<BlsScChia>::from_bytes(&v.legacy).unwrap();
      assert_eq!(legacy.to_bytes(), v.legacy);

      let ietf = BlsPublicKey::<BlsScIetf>::from_bytes(&v.ietf).unwrap();
      assert_eq!(ietf.to_bytes(), v.ietf);

      assert_ne!(v.legacy, v.ietf);
    }
  }

  #[cfg(feature = "serde")]
  #[test]
  fn serde_roundtrip() {
    let corpus = load_corpus_json(env!("CARGO_MANIFEST_DIR"), "bls_chia_ser_internals");
    let v = bls_pk_serialization(&corpus, "pk_serialization")
      .into_iter()
      .next()
      .unwrap();

    let chia = BlsPublicKey::<BlsScChia>::from_bytes(&v.legacy).unwrap();
    let json = to_string(&chia).unwrap();
    assert_eq!(from_str::<BlsPublicKey<BlsScChia>>(&json).unwrap(), chia);

    let ietf = BlsPublicKey::<BlsScIetf>::from_bytes(&v.ietf).unwrap();
    let json = to_string(&ietf).unwrap();
    assert_eq!(from_str::<BlsPublicKey<BlsScIetf>>(&json).unwrap(), ietf);
  }
}
