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

  /// Additively derive a child public key `self + tweak * G`,
  /// with `tweak` a 32-byte big-endian scalar.
  ///
  /// This is the public-side primitive for unhardened BIP32-style
  /// BLS derivation; it commutes with [`BlsSecretKey::add_tweak`]
  /// so that `sk.add_tweak(t).public_key() == pk.add_tweak(t)`.
  ///
  /// # Errors
  ///
  /// Returns `InvalidSecretKey` when `tweak` is zero or not below
  /// the group order, or `InvalidPublicKey` when the result is
  /// the point at infinity.
  pub fn add_tweak(&self, tweak: &[u8; 32]) -> Result<Self, BlsError> {
    let tweak_pk = BlsSecretKey::<S>::from_bytes(tweak)?.public_key();
    Self::aggregate(&[self, &tweak_pk])
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
#[expect(clippy::unwrap_used, reason = "test code")]
mod tests {
  use super::*;
  use crate::bls::tests::assert_dh_roundtrip;
  use crate::bls::{BlsScChia, BlsScIetf};

  use dash_dev::{bls_pk_serialization, load_corpus_json};
  use rstest::rstest;
  #[cfg(feature = "serde")]
  use serde_json::{from_str, to_string};

  #[rstest]
  #[case::chia(assert_dh_roundtrip::<BlsScChia>)]
  #[case::ietf(assert_dh_roundtrip::<BlsScIetf>)]
  fn dh_exchange_roundtrip(#[case] assertion: fn()) {
    assertion();
  }

  fn assert_add_tweak_commutes<S: BlsSchemeId + BlsScheme>() {
    let sk = BlsSecretKey::<S>::generate(&crate::tests::SEED_0).unwrap();
    let tweak = *BlsSecretKey::<S>::generate(&crate::tests::SEED_1).unwrap().to_bytes();

    // Deriving on the secret side then taking the public key must
    // equal deriving on the public side (unhardened BIP32 rule).
    let from_sk = sk.add_tweak(&tweak).unwrap().public_key();
    let from_pk = sk.public_key().add_tweak(&tweak).unwrap();
    assert_eq!(from_sk, from_pk);

    // Invalid tweaks are rejected on the public side too.
    assert!(sk.public_key().add_tweak(&[0u8; 32]).is_err());
  }

  #[rstest]
  #[case::chia(assert_add_tweak_commutes::<BlsScChia>)]
  #[case::ietf(assert_add_tweak_commutes::<BlsScIetf>)]
  fn add_tweak_commutes_with_secret(#[case] assertion: fn()) {
    assertion();
  }

  #[rstest]
  fn rejects_infinity_public_key() {
    // Dash Core rejects the point at infinity as a public key at
    // parse time (CBLSWrapper::SetBytes).
    let mut inf = [0u8; 48];
    inf[0] = 0xc0;
    assert_eq!(
      BlsPublicKey::<BlsScChia>::from_bytes(&inf).unwrap_err(),
      BlsError::InvalidPublicKey
    );
    assert_eq!(
      BlsPublicKey::<BlsScIetf>::from_bytes(&inf).unwrap_err(),
      BlsError::InvalidPublicKey
    );
  }

  #[rstest]
  #[case::low_bits_set({ let mut b = [0u8; 48]; b[0] = 0xc1; b })]
  #[case::tail_nonzero({ let mut b = [0u8; 48]; b[0] = 0xc0; b[47] = 0x01; b })]
  #[case::all_ones([0xffu8; 48])]
  fn rejects_non_canonical_infinity_public_key(#[case] bytes: [u8; 48]) {
    assert_eq!(
      BlsPublicKey::<BlsScChia>::from_bytes(&bytes).unwrap_err(),
      BlsError::InvalidPublicKey
    );
    assert_eq!(
      BlsPublicKey::<BlsScIetf>::from_bytes(&bytes).unwrap_err(),
      BlsError::InvalidPublicKey
    );
  }

  #[rstest]
  fn first_byte_sweep_rejects_zero_body() {
    // dashbls test.cpp "Should throw on a bad public key": every
    // first byte over a zero body must fail to parse. dashbls
    // itself accepts 0xc0 (canonical infinity) but Dash Core
    // rejects infinity keys at parse, and so do we.
    for first in 0..=0xffu16 {
      let mut b = [0u8; 48];
      b[0] = first as u8;
      assert!(
        BlsPublicKey::<BlsScChia>::from_bytes(&b).is_err(),
        "chia accepted first byte 0x{first:02x}"
      );
      assert!(
        BlsPublicKey::<BlsScIetf>::from_bytes(&b).is_err(),
        "ietf accepted first byte 0x{first:02x}"
      );
    }
  }

  #[rstest]
  #[case::infinity_tail_nonzero(
    "c00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001"
  )]
  #[case::infinity_body_nonzero(
    "c08000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
  )]
  #[case::infinity_extra_bit_0x08(
    "c80000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
  )]
  #[case::infinity_sign_bit(
    "e00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
  )]
  #[case::infinity_extra_bit_0x10(
    "d00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
  )]
  #[case::zero_x_not_in_group(
    "800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
  )]
  #[case::infinity_without_compression(
    "400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
  )]
  fn ietf_rejects_chia_bls_invalid_g1_vectors(#[case] hex: &str) {
    // Ported from chia-bls public_key.rs test_from_bytes_failures.
    // chia-bls classifies these as NotCanonical / InfinityNotZero /
    // InfinityInvalidBits; all must fail IETF parse here.
    let bytes = crate::tests::hex_to_48(hex);
    assert_eq!(
      BlsPublicKey::<BlsScIetf>::from_bytes(&bytes).unwrap_err(),
      BlsError::InvalidPublicKey
    );
  }

  #[rstest]
  #[case::x_4("800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004")]
  #[case::x_4_neg_y("a00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004")]
  #[case::x_5("800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000005")]
  fn rejects_on_curve_but_not_in_subgroup_g1(#[case] hex: &str) {
    // On-curve points outside the prime-order subgroup, verified
    // with bls12_381 0.8.0 (from_compressed_unchecked succeeds,
    // is_torsion_free is false), following its test_is_torsion_free.
    // Both schemes must reject them via the subgroup check.
    let bytes = crate::tests::hex_to_48(hex);
    assert_eq!(
      BlsPublicKey::<BlsScIetf>::from_bytes(&bytes).unwrap_err(),
      BlsError::InvalidPublicKey
    );
    assert_eq!(
      BlsPublicKey::<BlsScChia>::from_bytes(&bytes).unwrap_err(),
      BlsError::InvalidPublicKey
    );
  }

  fn assert_pk_roundtrip_canonical<S: crate::bls::BlsSchemeId + crate::bls::scheme_ops::BlsScheme>(corpus: &str) {
    // CheckMalleable-style property from Dash Core: parsing a
    // valid encoding and reserializing must reproduce the exact
    // input bytes for every corpus vector.
    let f = load_corpus_json(env!("CARGO_MANIFEST_DIR"), corpus);
    for v in dash_dev::bls_keygen(&f, "derive_pk") {
      let pk = BlsPublicKey::<S>::from_bytes(&v.pk).unwrap();
      assert_eq!(pk.to_bytes(), v.pk);
    }
  }

  #[rstest]
  #[case::chia(assert_pk_roundtrip_canonical::<BlsScChia>, "bls_chia_keygen")]
  #[case::ietf(assert_pk_roundtrip_canonical::<BlsScIetf>, "bls_ietf_keygen")]
  fn roundtrip_is_canonical_for_corpus_vectors(#[case] assertion: fn(&str), #[case] corpus: &str) {
    assertion(corpus);
  }

  #[rstest]
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
  #[rstest]
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
