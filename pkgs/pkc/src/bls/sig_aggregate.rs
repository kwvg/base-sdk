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
use super::{BlsScIetf, BlsSchemeId};
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
}

impl BlsSignature<BlsScIetf> {
  /// Verify an aggregated signature where each signer signed a
  /// distinct message. IETF only.
  pub fn verify_aggregates(&self, msgs: &[&[u8]], pks: &[&BlsPublicKey<BlsScIetf>]) -> Result<(), BlsError> {
    let inner_pks: Vec<_> = pks.iter().map(|k| &k.0).collect();
    BlsScIetf::verify_aggregates(&self.0, msgs, &inner_pks)
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
