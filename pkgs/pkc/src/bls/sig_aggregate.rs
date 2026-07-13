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

impl<S: BlsSchemeId + BlsScheme> BlsSignature<S> {
  /// Aggregate multiple signatures into one.
  pub fn aggregate(sigs: &[&Self]) -> Result<Self, BlsError> {
    let inner_refs: crate::prelude::Vec<&S::InnerSig> = sigs.iter().map(|s| &s.0).collect();
    S::aggregate_sig(&inner_refs).map(Self::from_inner)
  }

  /// Verify an aggregated signature where every signer signed
  /// the same message.
  pub fn fast_verify_aggregates(&self, msg: &[u8], pks: &[&BlsPublicKey<S>]) -> Result<(), BlsError> {
    let inner_pks: crate::prelude::Vec<&S::InnerPk> = pks.iter().map(|k| &k.0).collect();
    S::fast_verify_aggregates(&self.0, msg, &inner_pks)
  }

  /// Securely aggregate and verify signatures with public-key
  /// weighting.
  pub fn secure_verify_aggregates(&self, msg: &[u8], pks: &[&BlsPublicKey<S>]) -> Result<(), BlsError> {
    let inner_pks: crate::prelude::Vec<&S::InnerPk> = pks.iter().map(|k| &k.0).collect();
    S::secure_verify_aggregates(&self.0, msg, &inner_pks)
  }
}

impl BlsSignature<BlsScIetf> {
  /// Verify an aggregated signature where each signer signed a
  /// distinct message. IETF only.
  pub fn verify_aggregates(&self, msgs: &[&[u8]], pks: &[&BlsPublicKey<BlsScIetf>]) -> Result<(), BlsError> {
    let inner_pks: crate::prelude::Vec<_> = pks.iter().map(|k| &k.0).collect();
    BlsScIetf::verify_aggregates(&self.0, msgs, &inner_pks)
  }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "test code")]
mod tests {
  use crate::bls::{BlsPublicKey, BlsScChia, BlsScIetf, BlsSecretKey, BlsSignature};
  use crate::tests::*;

  use alloc::{vec, vec::Vec};
  use hex_literal::hex;
  use rstest::*;

  type ChiaSk = BlsSecretKey<BlsScChia>;
  type IetfSk = BlsSecretKey<BlsScIetf>;

  #[rstest]
  fn chia_aggregate_and_verify() {
    let sk0 = ChiaSk::generate(&SEED_0).unwrap();
    let sk1 = ChiaSk::generate(&SEED_1).unwrap();
    let msg = [0xabu8; 32];
    let sig1 = sk0.sign(&msg);
    let sig2 = sk1.sign(&msg);
    let agg = BlsSignature::aggregate(&[&sig1, &sig2]).unwrap();
    let pk1 = sk0.public_key();
    let pk2 = sk1.public_key();
    assert!(agg.fast_verify_aggregates(&msg, &[&pk1, &pk2]).is_ok());
  }

  #[rstest]
  fn chia_aggregate_empty_fails() {
    let empty_pk: Vec<&crate::bls::BlsPublicKey<BlsScChia>> = vec![];
    assert!(BlsPublicKey::aggregate(&empty_pk).is_err());
    let empty_sig: Vec<&BlsSignature<BlsScChia>> = vec![];
    assert!(BlsSignature::aggregate(&empty_sig).is_err());
  }

  #[rstest]
  fn chia_secure_verify_rejects_naive() {
    let sk0 = ChiaSk::generate(&SEED_0).unwrap();
    let sk1 = ChiaSk::generate(&SEED_1).unwrap();
    let msg = [0xabu8; 32];
    let sig1 = sk0.sign(&msg);
    let sig2 = sk1.sign(&msg);
    let agg = BlsSignature::aggregate(&[&sig1, &sig2]).unwrap();
    let pk1 = sk0.public_key();
    let pk2 = sk1.public_key();
    assert!(agg.fast_verify_aggregates(&msg, &[&pk1, &pk2]).is_ok());
    assert!(agg.secure_verify_aggregates(&msg, &[&pk1, &pk2]).is_err());
  }

  #[rstest]
  fn chia_secure_aggregate_order_independent() {
    let sk1 = ChiaSk::generate(&SEED_1).unwrap();
    let sk2 = ChiaSk::generate(&[2u8; 32]).unwrap();
    let sk3 = ChiaSk::generate(&[3u8; 32]).unwrap();

    let msg = [0xffu8; 32];
    let pk1 = sk1.public_key();
    let pk2 = sk2.public_key();
    let pk3 = sk3.public_key();
    let sig1 = sk1.sign(&msg);
    let sig2 = sk2.sign(&msg);
    let sig3 = sk3.sign(&msg);

    let agg_a = BlsSignature::aggregate(&[&sig1, &sig2, &sig3]).unwrap();
    let agg_b = BlsSignature::aggregate(&[&sig3, &sig1, &sig2]).unwrap();

    assert_eq!(agg_a.to_bytes(), agg_b.to_bytes());
    assert!(agg_a.fast_verify_aggregates(&msg, &[&pk1, &pk2, &pk3]).is_ok());
    assert!(agg_a.fast_verify_aggregates(&msg, &[&pk3, &pk1, &pk2]).is_ok());
  }

  #[rstest]
  fn ietf_aggregate_pk_roundtrip() {
    let sk0 = IetfSk::generate(&SEED_0).unwrap();
    let sk1 = IetfSk::generate(&SEED_1).unwrap();
    let pk1 = sk0.public_key();
    let pk2 = sk1.public_key();
    let agg = BlsPublicKey::aggregate(&[&pk1, &pk2]).unwrap();
    assert_eq!(agg.to_bytes().len(), 48);
  }

  #[rstest]
  fn ietf_aggregate_empty_fails() {
    let empty_pk: Vec<&crate::bls::BlsPublicKey<BlsScIetf>> = vec![];
    assert!(BlsPublicKey::aggregate(&empty_pk).is_err());
    let empty_sig: Vec<&BlsSignature<BlsScIetf>> = vec![];
    assert!(BlsSignature::aggregate(&empty_sig).is_err());
  }

  #[rstest]
  fn ietf_aggregate_two_distinct_messages() {
    let sk1 = IetfSk::generate(&SEED_0).unwrap();
    let sk2 = IetfSk::generate(&SEED_1).unwrap();

    let msg1 = hex!("070809");
    let msg2 = hex!("0a0b0c");
    let sig1 = sk1.sign(&msg1);
    let sig2 = sk2.sign(&msg2);
    let agg = BlsSignature::aggregate(&[&sig1, &sig2]).unwrap();

    let pk1 = sk1.public_key();
    let pk2 = sk2.public_key();
    let msgs: Vec<&[u8]> = vec![msg1.as_slice(), msg2.as_slice()];
    assert!(agg.verify_aggregates(&msgs, &[&pk1, &pk2]).is_ok());
  }

  #[rstest]
  fn ietf_fast_verify_same_message() {
    let sk0 = IetfSk::generate(&SEED_0).unwrap();
    let sk1 = IetfSk::generate(&SEED_1).unwrap();
    let msg = b"same message for both signers";
    let sig1 = sk0.sign(msg);
    let sig2 = sk1.sign(msg);
    let agg = BlsSignature::aggregate(&[&sig1, &sig2]).unwrap();
    let pk1 = sk0.public_key();
    let pk2 = sk1.public_key();
    assert!(agg.fast_verify_aggregates(msg, &[&pk1, &pk2]).is_ok());
  }

  #[rstest]
  fn ietf_fast_verify_order_independent() {
    let sk1 = IetfSk::generate(&SEED_1).unwrap();
    let sk2 = IetfSk::generate(&[2u8; 32]).unwrap();
    let sk3 = IetfSk::generate(&[3u8; 32]).unwrap();
    let msg = b"order test";
    let pk1 = sk1.public_key();
    let pk2 = sk2.public_key();
    let pk3 = sk3.public_key();
    let sig1 = sk1.sign(msg);
    let sig2 = sk2.sign(msg);
    let sig3 = sk3.sign(msg);
    let agg = BlsSignature::aggregate(&[&sig1, &sig2, &sig3]).unwrap();

    assert!(agg.fast_verify_aggregates(msg, &[&pk1, &pk2, &pk3]).is_ok());
    assert!(agg.fast_verify_aggregates(msg, &[&pk3, &pk1, &pk2]).is_ok());
  }

  #[rstest]
  fn ietf_secure_verify_rejects_naive_aggregate() {
    let sk0 = IetfSk::generate(&SEED_0).unwrap();
    let sk1 = IetfSk::generate(&SEED_1).unwrap();

    let msg = b"secure test";
    let sig1 = sk0.sign(msg);
    let sig2 = sk1.sign(msg);
    let agg = BlsSignature::aggregate(&[&sig1, &sig2]).unwrap();
    let pk1 = sk0.public_key();
    let pk2 = sk1.public_key();

    assert!(agg.fast_verify_aggregates(msg, &[&pk1, &pk2]).is_ok());
    assert!(agg.secure_verify_aggregates(msg, &[&pk1, &pk2]).is_err());
  }

  mod kat {
    use crate::bls::{BlsPublicKey, BlsSecretKey, BlsSignature};
    use crate::tests::{self, decode_hex, VectorFile};

    use alloc::{string::String, vec::Vec};
    use hex_conservative::DisplayHex;
    use serde::Deserialize;

    #[derive(Deserialize)]
    struct AggregatePkVector {
      pks: Vec<String>,
      agg_pk: String,
    }

    #[derive(Deserialize)]
    struct AggregateSigVector {
      sigs: Vec<String>,
      agg_sig: String,
    }

    #[derive(Deserialize)]
    struct AggregateSkVector {
      sks: Vec<String>,
      agg_sk: String,
    }

    #[derive(Deserialize)]
    #[expect(dead_code, reason = "deserialized from corpus JSON")]
    struct SecureAggVector {
      msg: String,
      pks: Vec<String>,
      sigs: Vec<String>,
      agg_sig_secure: String,
    }

    #[test]
    fn kat_chia_aggregate_pk() {
      let f: VectorFile = tests::load("bls_chia_aggregate");
      let vecs: Vec<AggregatePkVector> = tests::parse_sub(&f, "aggregate_pk");

      for v in &vecs {
        let pks: Vec<BlsPublicKey<crate::bls::BlsScChia>> = v
          .pks
          .iter()
          .map(|h| {
            let b: [u8; 48] = decode_hex(h).try_into().unwrap();
            BlsPublicKey::from_bytes(&b).unwrap()
          })
          .collect();
        let pk_refs: Vec<_> = pks.iter().collect();
        let agg = BlsPublicKey::aggregate(&pk_refs).unwrap();
        assert_eq!(agg.to_bytes().to_lower_hex_string(), v.agg_pk);
      }
    }

    #[test]
    fn kat_chia_aggregate_sig() {
      let f: VectorFile = tests::load("bls_chia_aggregate");
      let vecs: Vec<AggregateSigVector> = tests::parse_sub(&f, "aggregate_sig");

      for v in &vecs {
        let sigs: Vec<BlsSignature<crate::bls::BlsScChia>> = v
          .sigs
          .iter()
          .map(|h| {
            let b: [u8; 96] = decode_hex(h).try_into().unwrap();
            BlsSignature::from_bytes(&b).unwrap()
          })
          .collect();
        let sig_refs: Vec<_> = sigs.iter().collect();
        let agg = BlsSignature::aggregate(&sig_refs).unwrap();
        assert_eq!(agg.to_bytes().to_lower_hex_string(), v.agg_sig);
      }
    }

    #[test]
    fn kat_chia_secure_verify_aggregates() {
      let f: VectorFile = tests::load("bls_chia_secure_aggregate");
      let vecs: Vec<SecureAggVector> = tests::parse_sub(&f, "secure_verify_aggregates");

      for v in &vecs {
        let msg: [u8; 32] = decode_hex(&v.msg).try_into().unwrap();
        let pks: Vec<BlsPublicKey<crate::bls::BlsScChia>> = v
          .pks
          .iter()
          .map(|h| {
            let b: [u8; 48] = decode_hex(h).try_into().unwrap();
            BlsPublicKey::from_bytes(&b).unwrap()
          })
          .collect();

        let expected_agg: [u8; 96] = decode_hex(&v.agg_sig_secure).try_into().unwrap();
        let agg_sig = BlsSignature::<crate::bls::BlsScChia>::from_bytes(&expected_agg).unwrap();
        let pk_refs: Vec<_> = pks.iter().collect();

        assert!(
          agg_sig.secure_verify_aggregates(&msg, &pk_refs).is_ok(),
          "secure verify failed for n={}",
          v.pks.len()
        );
      }
    }

    #[test]
    fn kat_ietf_aggregate_pk() {
      let f: VectorFile = tests::load("bls_ietf_aggregate");
      let vecs: Vec<AggregatePkVector> = tests::parse_sub(&f, "aggregate_pk");

      for v in &vecs {
        let pks: Vec<BlsPublicKey<crate::bls::BlsScIetf>> = v
          .pks
          .iter()
          .map(|h| {
            let b: [u8; 48] = decode_hex(h).try_into().unwrap();
            BlsPublicKey::from_bytes(&b).unwrap()
          })
          .collect();
        let pk_refs: Vec<_> = pks.iter().collect();
        let agg = BlsPublicKey::aggregate(&pk_refs).unwrap();
        assert_eq!(agg.to_bytes().to_lower_hex_string(), v.agg_pk);
      }
    }

    #[test]
    fn kat_ietf_aggregate_sig() {
      let f: VectorFile = tests::load("bls_ietf_aggregate");
      let vecs: Vec<AggregateSigVector> = tests::parse_sub(&f, "aggregate_sig");

      for v in &vecs {
        let sigs: Vec<BlsSignature<crate::bls::BlsScIetf>> = v
          .sigs
          .iter()
          .map(|h| {
            let b: [u8; 96] = decode_hex(h).try_into().unwrap();
            BlsSignature::from_bytes(&b).unwrap()
          })
          .collect();
        let sig_refs: Vec<_> = sigs.iter().collect();
        let agg = BlsSignature::aggregate(&sig_refs).unwrap();
        assert_eq!(agg.to_bytes().to_lower_hex_string(), v.agg_sig);
      }
    }

    #[test]
    fn kat_ietf_aggregate_sk() {
      let f: VectorFile = tests::load("bls_aggregate");
      let vecs: Vec<AggregateSkVector> = tests::parse_sub(&f, "aggregate_sk");

      for v in &vecs {
        let sks: Vec<BlsSecretKey<crate::bls::BlsScIetf>> = v
          .sks
          .iter()
          .map(|h| {
            let b: [u8; 32] = decode_hex(h).try_into().unwrap();
            BlsSecretKey::from_bytes(&b).unwrap()
          })
          .collect();
        let sk_refs: Vec<_> = sks.iter().collect();
        let agg = BlsSecretKey::aggregate(&sk_refs).unwrap();
        assert_eq!(agg.to_bytes().to_lower_hex_string(), v.agg_sk);
      }
    }

    #[test]
    fn kat_ietf_secure_verify_aggregates() {
      let f: VectorFile = tests::load("bls_ietf_secure_aggregate");
      let vecs: Vec<SecureAggVector> = tests::parse_sub(&f, "secure_verify_aggregates");

      for v in &vecs {
        let msg = decode_hex(&v.msg);
        let pks: Vec<BlsPublicKey<crate::bls::BlsScIetf>> = v
          .pks
          .iter()
          .map(|h| {
            let b: [u8; 48] = decode_hex(h).try_into().unwrap();
            BlsPublicKey::from_bytes(&b).unwrap()
          })
          .collect();

        let expected_agg: [u8; 96] = decode_hex(&v.agg_sig_secure).try_into().unwrap();
        let agg_sig = BlsSignature::<crate::bls::BlsScIetf>::from_bytes(&expected_agg).unwrap();
        let pk_refs: Vec<_> = pks.iter().collect();

        assert!(
          agg_sig.secure_verify_aggregates(&msg, &pk_refs).is_ok(),
          "secure verify failed for n={}",
          v.pks.len()
        );
      }
    }
  }
}
