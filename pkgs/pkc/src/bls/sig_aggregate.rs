//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! BLS signature aggregation and aggregate verification.

use super::error::BlsError;
use super::public_ops::BlsPublicKey;
use super::scheme_ops::BlsScheme;
use super::sig_basic::BlsSignature;
use super::{BlsSchemeId, BlsSigId};
use crate::prelude::*;

impl<S: BlsSchemeId + BlsScheme> BlsSignature<S> {
  /// Aggregate multiple signatures into one.
  pub fn aggregate(sigs: &[&Self]) -> Result<Self, BlsError> {
    let inner_refs: Vec<&S::InnerSig> = sigs.iter().map(|s| &s.0).collect();
    S::aggregate_sig(&inner_refs).map(Self::from_inner)
  }

  /// Verify an aggregated signature where every signer signed
  /// the same message.
  pub fn fast_verify_aggregates(&self, msg: &[u8], pks: &[&BlsPublicKey<S>]) -> Result<(), BlsError> {
    let inner_pks: Vec<&S::InnerPk> = pks.iter().map(|k| &k.0).collect();
    S::fast_verify_aggregates(&self.0, msg, &inner_pks)
  }

  /// Securely aggregate and verify signatures with public-key
  /// weighting.
  pub fn secure_verify_aggregates(&self, msg: &[u8], pks: &[&BlsPublicKey<S>]) -> Result<(), BlsError> {
    let inner_pks: Vec<&S::InnerPk> = pks.iter().map(|k| &k.0).collect();
    S::secure_verify_aggregates(&self.0, msg, &inner_pks)
  }

  /// Securely aggregate signatures with the same public-key
  /// weighting used by secure verification (dashbls
  /// `CoreMPL::AggregateSecure`); the result verifies with
  /// [`Self::secure_verify_aggregates`].
  ///
  /// # Errors
  ///
  /// Returns `CountMismatch` when the slices differ in length,
  /// `EmptyAggregation` without inputs, or `InvalidSignature`
  /// when the weighted sum degenerates to infinity.
  pub fn aggregate_secure(sigs: &[&Self], pks: &[&BlsPublicKey<S>]) -> Result<Self, BlsError> {
    let inner_pks: Vec<&S::InnerPk> = pks.iter().map(|k| &k.0).collect();
    let inner_sigs: Vec<&S::InnerSig> = sigs.iter().map(|s| &s.0).collect();
    S::aggregate_sig_secure(&inner_pks, &inner_sigs).map(Self::from_inner)
  }

  /// Subtract a signature from this one (dashbls
  /// `CBLSSignature::SubInsecure`).
  ///
  /// # Errors
  ///
  /// Returns `InvalidSignature` when the difference is the point
  /// at infinity (subtracting a signature from itself).
  pub fn sub_insecure(&self, other: &Self) -> Result<Self, BlsError> {
    S::sub_sig(&self.0, &other.0).map(Self::from_inner)
  }

  /// Verify an aggregated signature over per-signer messages.
  ///
  /// The IETF scheme enforces the basic scheme's distinct
  /// message rule; the legacy scheme matches dashbls
  /// `LegacySchemeMPL::AggregateVerify` (32-byte hashes, no
  /// distinctness requirement).
  ///
  /// # Errors
  ///
  /// Returns `CountMismatch`, `EmptyAggregation`,
  /// `DuplicateMessage` (IETF), `InvalidMessageLength` (legacy)
  /// or `VerifyFailed`.
  pub fn verify_aggregates(&self, msgs: &[&[u8]], pks: &[&BlsPublicKey<S>]) -> Result<(), BlsError> {
    let inner_pks: Vec<&S::InnerPk> = pks.iter().map(|k| &k.0).collect();
    S::verify_aggregates(&self.0, msgs, &inner_pks)
  }

  /// Verify an aggregated signature over per-signer messages
  /// under a specific signature scheme variant.
  ///
  /// # Errors
  ///
  /// As [`Self::verify_aggregates`], plus `UnsupportedScheme`
  /// for variants the scheme does not implement.
  pub fn verify_aggregates_with(
    &self,
    msgs: &[&[u8]],
    pks: &[&BlsPublicKey<S>],
    scheme: BlsSigId,
  ) -> Result<(), BlsError> {
    let inner_pks: Vec<&S::InnerPk> = pks.iter().map(|k| &k.0).collect();
    S::verify_aggregates_with(&self.0, msgs, &inner_pks, scheme)
  }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "test code")]
mod tests {
  use crate::bls::tests::{
    assert_aggregate_order_independent, assert_empty_aggregation_rejected, assert_fast_aggregate_verifies,
    assert_secure_aggregate_rejects_naive,
  };
  use crate::bls::{BlsScChia, BlsScIetf, BlsSecretKey, BlsSignature};
  use crate::prelude::*;
  use crate::tests::*;

  use hex_literal::hex;
  use rstest::*;

  #[rstest]
  #[case::chia(assert_fast_aggregate_verifies::<BlsScChia>)]
  #[case::ietf(assert_fast_aggregate_verifies::<BlsScIetf>)]
  fn fast_aggregate_verifies(#[case] assertion: fn()) {
    assertion();
  }

  #[rstest]
  #[case::chia(assert_empty_aggregation_rejected::<BlsScChia>)]
  #[case::ietf(assert_empty_aggregation_rejected::<BlsScIetf>)]
  fn aggregate_empty_fails(#[case] assertion: fn()) {
    assertion();
  }

  #[rstest]
  #[case::chia(assert_secure_aggregate_rejects_naive::<BlsScChia>)]
  #[case::ietf(assert_secure_aggregate_rejects_naive::<BlsScIetf>)]
  fn secure_verify_rejects_naive(#[case] assertion: fn()) {
    assertion();
  }

  #[rstest]
  #[case::chia(assert_aggregate_order_independent::<BlsScChia>)]
  #[case::ietf(assert_aggregate_order_independent::<BlsScIetf>)]
  fn aggregate_order_independent(#[case] assertion: fn()) {
    assertion();
  }

  #[rstest]
  fn ietf_aggregate_two_distinct_messages() {
    let sk1 = BlsSecretKey::<BlsScIetf>::generate(&SEED_0).unwrap();
    let sk2 = BlsSecretKey::<BlsScIetf>::generate(&SEED_1).unwrap();

    let msg1 = hex!("070809");
    let msg2 = hex!("0a0b0c");
    let sig1 = sk1.sign(&msg1).unwrap();
    let sig2 = sk2.sign(&msg2).unwrap();
    let agg = BlsSignature::aggregate(&[&sig1, &sig2]).unwrap();

    let pk1 = sk1.public_key();
    let pk2 = sk2.public_key();
    let msgs: Vec<&[u8]> = vec![msg1.as_slice(), msg2.as_slice()];
    assert!(agg.verify_aggregates(&msgs, &[&pk1, &pk2]).is_ok());
  }

  #[rstest]
  fn ietf_basic_rejects_duplicate_messages() {
    let sk1 = BlsSecretKey::<BlsScIetf>::generate(&SEED_0).unwrap();
    let sk2 = BlsSecretKey::<BlsScIetf>::generate(&SEED_1).unwrap();

    let sig1 = sk1.sign(&MSG_DEADBEEF).unwrap();
    let sig2 = sk2.sign(&MSG_DEADBEEF).unwrap();
    let agg = BlsSignature::aggregate(&[&sig1, &sig2]).unwrap();

    let pk1 = sk1.public_key();
    let pk2 = sk2.public_key();
    let msgs: Vec<&[u8]> = vec![&MSG_DEADBEEF, &MSG_DEADBEEF];
    // BasicSchemeMPL requires distinct messages.
    assert_eq!(
      agg.verify_aggregates(&msgs, &[&pk1, &pk2]).unwrap_err(),
      crate::bls::BlsError::DuplicateMessage
    );
  }

  #[rstest]
  fn chia_verify_aggregates_distinct_messages() {
    // LegacySchemeMPL::AggregateVerify semantics: per-signer
    // 32-byte hashes, repeats allowed, order significant.
    let sk1 = BlsSecretKey::<BlsScChia>::generate(&SEED_0).unwrap();
    let sk2 = BlsSecretKey::<BlsScChia>::generate(&SEED_1).unwrap();
    let msg1 = test_msg(1);
    let msg2 = test_msg(2);

    let sig1 = sk1.sign(&msg1).unwrap();
    let sig2 = sk2.sign(&msg2).unwrap();
    let agg = BlsSignature::aggregate(&[&sig1, &sig2]).unwrap();

    let pk1 = sk1.public_key();
    let pk2 = sk2.public_key();
    let msgs: Vec<&[u8]> = vec![&msg1, &msg2];
    assert!(agg.verify_aggregates(&msgs, &[&pk1, &pk2]).is_ok());

    let swapped: Vec<&[u8]> = vec![&msg2, &msg1];
    assert!(agg.verify_aggregates(&swapped, &[&pk1, &pk2]).is_err());

    // Same message twice is allowed in legacy mode.
    let sig2_same = sk2.sign(&msg1).unwrap();
    let agg_same = BlsSignature::aggregate(&[&sig1, &sig2_same]).unwrap();
    let same: Vec<&[u8]> = vec![&msg1, &msg1];
    assert!(agg_same.verify_aggregates(&same, &[&pk1, &pk2]).is_ok());

    // Legacy signing covers 32-byte hashes only.
    let short: Vec<&[u8]> = vec![&msg1[..16], &msg2];
    assert_eq!(
      agg.verify_aggregates(&short, &[&pk1, &pk2]).unwrap_err(),
      crate::bls::BlsError::InvalidMessageLength
    );
  }

  fn assert_aggregate_secure_matches_corpus<S: crate::bls::BlsSchemeId + crate::bls::scheme_ops::BlsScheme>(
    corpus: &str,
  ) {
    use crate::bls::BlsPublicKey;
    use dash_dev::{bls_secure_aggregate, load_corpus_json};

    let f = load_corpus_json(env!("CARGO_MANIFEST_DIR"), corpus);
    for v in bls_secure_aggregate(&f, "secure_verify_aggregates") {
      let pks: Vec<BlsPublicKey<S>> = v.pks.iter().map(|pk| BlsPublicKey::from_bytes(pk).unwrap()).collect();
      let sigs: Vec<BlsSignature<S>> = v
        .sigs
        .iter()
        .map(|sig| BlsSignature::from_bytes(sig).unwrap())
        .collect();
      let pk_refs: Vec<_> = pks.iter().collect();
      let sig_refs: Vec<_> = sigs.iter().collect();

      let agg = BlsSignature::aggregate_secure(&sig_refs, &pk_refs).unwrap();
      assert_eq!(agg.to_bytes(), v.aggregate, "aggregate_secure diverges from corpus");
      assert!(agg.secure_verify_aggregates(&v.msg, &pk_refs).is_ok());
    }
  }

  #[rstest]
  #[case::chia(
    assert_aggregate_secure_matches_corpus::<BlsScChia>,
    "bls_chia_secure_aggregate",
  )]
  #[case::ietf(
    assert_aggregate_secure_matches_corpus::<BlsScIetf>,
    "bls_ietf_secure_aggregate",
  )]
  fn aggregate_secure_matches_corpus(#[case] assertion: fn(&str), #[case] corpus: &str) {
    assertion(corpus);
  }

  fn assert_sub_insecure_roundtrip<S: crate::bls::BlsSchemeId + crate::bls::scheme_ops::BlsScheme>() {
    let sk1 = BlsSecretKey::<S>::generate(&SEED_0).unwrap();
    let sk2 = BlsSecretKey::<S>::generate(&SEED_1).unwrap();
    let sig1 = sk1.sign(&MSG_DEADBEEF).unwrap();
    let sig2 = sk2.sign(&MSG_DEADBEEF).unwrap();

    // CBLSSignature::SubInsecure inverts aggregation.
    let agg = BlsSignature::aggregate(&[&sig1, &sig2]).unwrap();
    assert_eq!(agg.sub_insecure(&sig2).unwrap(), sig1);
    assert_eq!(agg.sub_insecure(&sig1).unwrap(), sig2);

    // Subtracting a signature from itself yields infinity.
    assert_eq!(
      sig1.sub_insecure(&sig1).unwrap_err(),
      crate::bls::BlsError::InvalidSignature
    );
  }

  #[rstest]
  #[case::chia(assert_sub_insecure_roundtrip::<BlsScChia>)]
  #[case::ietf(assert_sub_insecure_roundtrip::<BlsScIetf>)]
  fn sub_insecure_roundtrip(#[case] assertion: fn()) {
    assertion();
  }

  #[rstest]
  fn aug_aggregate_of_aggregates_matches_dashbls() {
    // dashbls test.cpp "Chia test vector 2 (Augmented, aggregate
    // of aggregates)": nested aggregation, repeated messages
    // disambiguated by the pk prefix, pinned aggregate bytes.
    use crate::bls::BlsSigId;

    let msg1: &[u8] = &[1, 2, 3, 40];
    let msg2: &[u8] = &[5, 6, 70, 201];
    let msg3: &[u8] = &[9, 10, 11, 12, 13];
    let msg4: &[u8] = &[15, 63, 244, 92, 0, 1];

    let sk1 = BlsSecretKey::<BlsScIetf>::generate(&[0x02u8; 32]).unwrap();
    let sk2 = BlsSecretKey::<BlsScIetf>::generate(&[0x03u8; 32]).unwrap();
    let pk1 = sk1.public_key();
    let pk2 = sk2.public_key();

    let aug = BlsSigId::MessageAugmentation;
    let sig1 = sk1.sign_with(msg1, aug).unwrap();
    let sig2 = sk2.sign_with(msg2, aug).unwrap();
    let sig3 = sk2.sign_with(msg1, aug).unwrap();
    let sig4 = sk1.sign_with(msg3, aug).unwrap();
    let sig5 = sk1.sign_with(msg1, aug).unwrap();
    let sig6 = sk1.sign_with(msg4, aug).unwrap();

    let agg_l = BlsSignature::aggregate(&[&sig1, &sig2]).unwrap();
    let agg_r = BlsSignature::aggregate(&[&sig3, &sig4, &sig5]).unwrap();
    let agg = BlsSignature::aggregate(&[&agg_l, &agg_r, &sig6]).unwrap();

    assert_eq!(
      agg.to_bytes(),
      hex!(
        "a1d5360dcb418d33b29b90b912b4accde535cf0e52caf467a005dc632d9f7af4"
        "4b6c4e9acd46eac218b28cdb07a3e3bc087df1cd1e3213aa4e11322a3ff3847b"
        "bba0b2fd19ddc25ca964871997b9bceeab37a4c2565876da19382ea32a962200"
      )
    );

    let pks = [&pk1, &pk2, &pk2, &pk1, &pk1, &pk1];
    let msgs: Vec<&[u8]> = vec![msg1, msg2, msg1, msg3, msg1, msg4];
    assert!(agg.verify_aggregates_with(&msgs, &pks, aug).is_ok());
    // The repeated message means the basic scheme must refuse.
    assert_eq!(
      agg.verify_aggregates_with(&msgs, &pks, BlsSigId::Basic).unwrap_err(),
      crate::bls::BlsError::DuplicateMessage
    );
  }

  mod kat {
    use crate::bls::{BlsPublicKey, BlsScChia, BlsScIetf, BlsSecretKey, BlsSignature};
    use crate::prelude::*;

    use dash_dev::{bls_aggregate_pk, bls_aggregate_sig, bls_aggregate_sk, bls_secure_aggregate, load_corpus_json};
    use rstest::rstest;

    #[rstest]
    fn kat_chia_aggregate_pk() {
      let corpus = load_corpus_json(env!("CARGO_MANIFEST_DIR"), "bls_chia_aggregate");
      let vecs = bls_aggregate_pk(&corpus, "aggregate_pk");

      for v in &vecs {
        let pks: Vec<BlsPublicKey<BlsScChia>> = v.pks.iter().map(|pk| BlsPublicKey::from_bytes(pk).unwrap()).collect();
        let pk_refs: Vec<_> = pks.iter().collect();
        let agg = BlsPublicKey::aggregate(&pk_refs).unwrap();
        assert_eq!(agg.to_bytes(), v.aggregate);
      }
    }

    #[rstest]
    fn kat_chia_aggregate_sig() {
      let corpus = load_corpus_json(env!("CARGO_MANIFEST_DIR"), "bls_chia_aggregate");
      let vecs = bls_aggregate_sig(&corpus, "aggregate_sig");

      for v in &vecs {
        let sigs: Vec<BlsSignature<BlsScChia>> = v
          .sigs
          .iter()
          .map(|sig| BlsSignature::from_bytes(sig).unwrap())
          .collect();
        let sig_refs: Vec<_> = sigs.iter().collect();
        let agg = BlsSignature::aggregate(&sig_refs).unwrap();
        assert_eq!(agg.to_bytes(), v.aggregate);
      }
    }

    #[rstest]
    fn kat_chia_secure_verify_aggregates() {
      let corpus = load_corpus_json(env!("CARGO_MANIFEST_DIR"), "bls_chia_secure_aggregate");
      let vecs = bls_secure_aggregate(&corpus, "secure_verify_aggregates");

      for v in &vecs {
        let pks: Vec<BlsPublicKey<BlsScChia>> = v.pks.iter().map(|pk| BlsPublicKey::from_bytes(pk).unwrap()).collect();

        let agg_sig = BlsSignature::<BlsScChia>::from_bytes(&v.aggregate).unwrap();
        let pk_refs: Vec<_> = pks.iter().collect();

        assert!(
          agg_sig.secure_verify_aggregates(&v.msg, &pk_refs).is_ok(),
          "secure verify failed for n={}",
          v.pks.len()
        );
      }
    }

    #[rstest]
    fn kat_ietf_aggregate_pk() {
      let corpus = load_corpus_json(env!("CARGO_MANIFEST_DIR"), "bls_ietf_aggregate");
      let vecs = bls_aggregate_pk(&corpus, "aggregate_pk");

      for v in &vecs {
        let pks: Vec<BlsPublicKey<BlsScIetf>> = v.pks.iter().map(|pk| BlsPublicKey::from_bytes(pk).unwrap()).collect();
        let pk_refs: Vec<_> = pks.iter().collect();
        let agg = BlsPublicKey::aggregate(&pk_refs).unwrap();
        assert_eq!(agg.to_bytes(), v.aggregate);
      }
    }

    #[rstest]
    fn kat_ietf_aggregate_sig() {
      let corpus = load_corpus_json(env!("CARGO_MANIFEST_DIR"), "bls_ietf_aggregate");
      let vecs = bls_aggregate_sig(&corpus, "aggregate_sig");

      for v in &vecs {
        let sigs: Vec<BlsSignature<BlsScIetf>> = v
          .sigs
          .iter()
          .map(|sig| BlsSignature::from_bytes(sig).unwrap())
          .collect();
        let sig_refs: Vec<_> = sigs.iter().collect();
        let agg = BlsSignature::aggregate(&sig_refs).unwrap();
        assert_eq!(agg.to_bytes(), v.aggregate);
      }
    }

    #[rstest]
    fn kat_ietf_aggregate_sk() {
      let corpus = load_corpus_json(env!("CARGO_MANIFEST_DIR"), "bls_aggregate");
      let vecs = bls_aggregate_sk(&corpus, "aggregate_sk");

      for v in &vecs {
        let sks: Vec<BlsSecretKey<BlsScIetf>> = v.sks.iter().map(|sk| BlsSecretKey::from_bytes(sk).unwrap()).collect();
        let sk_refs: Vec<_> = sks.iter().collect();
        let agg = BlsSecretKey::aggregate(&sk_refs).unwrap();
        assert_eq!(*agg.to_bytes(), v.aggregate);
      }
    }

    #[rstest]
    fn kat_ietf_secure_verify_aggregates() {
      let corpus = load_corpus_json(env!("CARGO_MANIFEST_DIR"), "bls_ietf_secure_aggregate");
      let vecs = bls_secure_aggregate(&corpus, "secure_verify_aggregates");

      for v in &vecs {
        let pks: Vec<BlsPublicKey<BlsScIetf>> = v.pks.iter().map(|pk| BlsPublicKey::from_bytes(pk).unwrap()).collect();

        let agg_sig = BlsSignature::<BlsScIetf>::from_bytes(&v.aggregate).unwrap();
        let pk_refs: Vec<_> = pks.iter().collect();

        assert!(
          agg_sig.secure_verify_aggregates(&v.msg, &pk_refs).is_ok(),
          "secure verify failed for n={}",
          v.pks.len()
        );
      }
    }
  }
}
