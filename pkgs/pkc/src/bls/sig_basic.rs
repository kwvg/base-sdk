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
#[expect(clippy::unwrap_used, reason = "test code")]
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
  fn rejects_infinity_signature() {
    // Dash Core rejects the point at infinity as a signature at
    // parse time (CBLSWrapper::SetBytes).
    let mut inf = [0u8; 96];
    inf[0] = 0xc0;
    assert_eq!(
      BlsSignature::<BlsScChia>::from_bytes(&inf).unwrap_err(),
      BlsError::InvalidSignature
    );
    assert_eq!(
      BlsSignature::<BlsScIetf>::from_bytes(&inf).unwrap_err(),
      BlsError::InvalidSignature
    );
  }

  #[rstest]
  #[case::low_bits_set({ let mut b = [0u8; 96]; b[0] = 0xc1; b })]
  #[case::tail_nonzero({ let mut b = [0u8; 96]; b[0] = 0xc0; b[95] = 0x01; b })]
  #[case::all_ones([0xffu8; 96])]
  fn rejects_non_canonical_infinity_signature(#[case] bytes: [u8; 96]) {
    assert_eq!(
      BlsSignature::<BlsScChia>::from_bytes(&bytes).unwrap_err(),
      BlsError::InvalidSignature
    );
    assert_eq!(
      BlsSignature::<BlsScIetf>::from_bytes(&bytes).unwrap_err(),
      BlsError::InvalidSignature
    );
  }

  #[rstest]
  #[case::empty(&[])]
  #[case::short(&[0x42; 31])]
  #[case::long(&[0x42; 33])]
  fn chia_rejects_non_32_byte_message(#[case] msg: &[u8]) {
    // dashbls signs and verifies 32-byte hashes only.
    let sk = BlsSecretKey::<BlsScChia>::generate(&SEED_0).unwrap();
    assert_eq!(sk.sign(msg).unwrap_err(), BlsError::InvalidMessageLength);

    let sig = sk.sign(&MSG_DEADBEEF).unwrap();
    assert_eq!(
      sig.verify(msg, &sk.public_key()).unwrap_err(),
      BlsError::InvalidMessageLength
    );
  }

  #[rstest]
  fn aug_sign_verify_roundtrip() {
    // AugSchemeMPL: signs pk || msg under the AUG dst, so the
    // same message signed by different keys hashes differently
    // and an aug signature never verifies under basic.
    use crate::bls::BlsSigId;

    let sk = BlsSecretKey::<BlsScIetf>::generate(&SEED_0).unwrap();
    let pk = sk.public_key();
    let msg = [1u8, 2, 3, 40];

    let sig = sk.sign_with(&msg, BlsSigId::MessageAugmentation).unwrap();
    assert!(sig.verify_with(&msg, &pk, BlsSigId::MessageAugmentation).is_ok());
    assert!(sig.verify_with(&msg, &pk, BlsSigId::Basic).is_err());
    assert!(sig.verify(&msg, &pk).is_err());

    let other = BlsSecretKey::<BlsScIetf>::generate(&crate::tests::SEED_1).unwrap();
    assert!(sig
      .verify_with(&msg, &other.public_key(), BlsSigId::MessageAugmentation)
      .is_err());
  }

  #[rstest]
  fn chia_rejects_augmentation_scheme() {
    use crate::bls::BlsSigId;

    // dashbls LegacySchemeMPL has no augmented variant.
    let sk = BlsSecretKey::<BlsScChia>::generate(&SEED_0).unwrap();
    assert_eq!(
      sk.sign_with(&MSG_DEADBEEF, BlsSigId::MessageAugmentation).unwrap_err(),
      BlsError::UnsupportedScheme
    );
  }

  #[rstest]
  fn ietf_signs_any_message_length() {
    let sk = BlsSecretKey::<BlsScIetf>::generate(&SEED_0).unwrap();
    for msg in [&[][..], &[0x42; 3][..], &[0x42; 64][..]] {
      let sig = sk.sign(msg).unwrap();
      assert!(sig.verify(msg, &sk.public_key()).is_ok());
    }
  }

  #[rstest]
  fn first_byte_sweep_rejects_zero_body() {
    // dashbls test.cpp "Should throw on a bad G2Element": every
    // first byte over a zero body must fail to parse. dashbls
    // itself accepts 0xc0 (canonical infinity) but Dash Core
    // rejects infinity signatures at parse, and so do we.
    for first in 0..=0xffu16 {
      let mut b = [0u8; 96];
      b[0] = first as u8;
      assert!(
        BlsSignature::<BlsScChia>::from_bytes(&b).is_err(),
        "chia accepted first byte 0x{first:02x}"
      );
      assert!(
        BlsSignature::<BlsScIetf>::from_bytes(&b).is_err(),
        "ietf accepted first byte 0x{first:02x}"
      );
    }

    // dashbls also requires the 48th byte to start with 0b000.
    let mut b = [0u8; 96];
    b[48] = 0xff;
    assert!(BlsSignature::<BlsScChia>::from_bytes(&b).is_err());
  }

  #[rstest]
  #[case::infinity_tail_nonzero(0xc0, 95, 0x01)]
  #[case::infinity_body_nonzero(0xc0, 1, 0x80)]
  #[case::infinity_extra_bit_0x08(0xc8, 0, 0)]
  #[case::infinity_sign_bit(0xe0, 0, 0)]
  #[case::infinity_extra_bit_0x10(0xd0, 0, 0)]
  #[case::zero_x_not_in_group(0x80, 0, 0)]
  #[case::infinity_without_compression(0x40, 0, 0)]
  fn ietf_rejects_chia_bls_invalid_g2_patterns(#[case] first: u8, #[case] idx: usize, #[case] val: u8) {
    // G2 analogues of the chia-bls invalid G1 flag recipes from
    // public_key.rs test_from_bytes_failures, applied to the
    // 96-byte IETF signature encoding.
    let mut bytes = [0u8; 96];
    bytes[0] = first;
    bytes[idx] |= val;
    assert_eq!(
      BlsSignature::<BlsScIetf>::from_bytes(&bytes).unwrap_err(),
      BlsError::InvalidSignature
    );
  }

  #[rstest]
  #[case::x_4("800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004")]
  #[case::x_4_neg_y("a00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004")]
  #[case::x_5("800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000005")]
  fn rejects_on_curve_but_not_in_subgroup_g2(#[case] hex: &str) {
    // On-curve points outside the prime-order subgroup, verified
    // with bls12_381 0.8.0 (from_compressed_unchecked succeeds,
    // is_torsion_free is false), following its test_is_torsion_free.
    // Both schemes must reject them; the legacy layout reads the
    // same bytes as a different x, which is equally invalid.
    let bytes = crate::tests::hex_to_96(hex);
    assert_eq!(
      BlsSignature::<BlsScIetf>::from_bytes(&bytes).unwrap_err(),
      BlsError::InvalidSignature
    );
    assert_eq!(
      BlsSignature::<BlsScChia>::from_bytes(&bytes).unwrap_err(),
      BlsError::InvalidSignature
    );
  }

  fn assert_sig_roundtrip_canonical<S: crate::bls::BlsSchemeId + crate::bls::scheme_ops::BlsScheme>(
    corpus: &str,
    sign_section: bool,
  ) {
    // CheckMalleable-style property from Dash Core: parsing a
    // valid encoding and reserializing must reproduce the exact
    // input bytes for every corpus vector.
    let f = load_corpus_json(env!("CARGO_MANIFEST_DIR"), corpus);
    let sigs: crate::prelude::Vec<[u8; 96]> = if sign_section {
      dash_dev::bls_sign(&f, "sign").into_iter().map(|v| v.sig).collect()
    } else {
      dash_dev::bls_aggregate_sig(&f, "aggregate_sig")
        .into_iter()
        .flat_map(|v| v.sigs.into_iter().chain([v.aggregate]))
        .collect()
    };
    for bytes in sigs {
      let sig = BlsSignature::<S>::from_bytes(&bytes).unwrap();
      assert_eq!(sig.to_bytes(), bytes);
    }
  }

  #[rstest]
  #[case::chia_sign(assert_sig_roundtrip_canonical::<BlsScChia>, "bls_chia_sign", true)]
  #[case::ietf_sign(assert_sig_roundtrip_canonical::<BlsScIetf>, "bls_ietf_sign", true)]
  #[case::chia_aggregate(assert_sig_roundtrip_canonical::<BlsScChia>, "bls_chia_aggregate", false)]
  #[case::ietf_aggregate(assert_sig_roundtrip_canonical::<BlsScIetf>, "bls_ietf_aggregate", false)]
  fn roundtrip_is_canonical_for_corpus_vectors(
    #[case] assertion: fn(&str, bool),
    #[case] corpus: &str,
    #[case] sign_section: bool,
  ) {
    assertion(corpus, sign_section);
  }

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
    let chia = chia_sk.sign(&MSG_DEADBEEF).unwrap();
    let json = to_string(&chia).unwrap();
    assert_eq!(from_str::<BlsSignature<BlsScChia>>(&json).unwrap(), chia);

    let ietf_sk = BlsSecretKey::<BlsScIetf>::generate(&SEED_0).unwrap();
    let ietf = ietf_sk.sign(&MSG_DEADBEEF).unwrap();
    let json = to_string(&ietf).unwrap();
    assert_eq!(from_str::<BlsSignature<BlsScIetf>>(&json).unwrap(), ietf);
  }

  #[rstest]
  fn signatures_differ_across_schemes() {
    let chia = BlsSecretKey::<BlsScChia>::generate(&SEED_0).unwrap();
    let ietf = BlsSecretKey::<BlsScIetf>::from_bytes(&chia.to_bytes()).unwrap();
    assert_ne!(
      chia.sign(&MSG_DEADBEEF).unwrap().to_bytes(),
      ietf.sign(&MSG_DEADBEEF).unwrap().to_bytes()
    );
  }

  #[rstest]
  #[case::chia(assert_signing_roundtrip::<BlsScChia>)]
  #[case::ietf(assert_signing_roundtrip::<BlsScIetf>)]
  fn signing_roundtrip_and_rejections(#[case] assertion: fn()) {
    assertion();
  }
}
