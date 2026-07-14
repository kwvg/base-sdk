//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Threshold share types and secret-key splitting.

use super::error::BlsError;
use super::public_ops::BlsPublicKey;
use super::scheme_ops::{self, BlsScheme};
use super::secret_ops::BlsSecretKey;
use super::sig_basic::BlsSignature;
use super::BlsSchemeId;
use crate::prelude::*;

use dash_num::Hash256;
use rand_core::CryptoRngCore;

use core::fmt::{Debug, Formatter, Result as FmtResult};

/// Secret key share for threshold signing.
pub struct BlsSkShare<S: BlsSchemeId + BlsScheme> {
  id: Hash256,
  sk: BlsSecretKey<S>,
}

impl<S: BlsSchemeId + BlsScheme> Clone for BlsSkShare<S> {
  fn clone(&self) -> Self {
    Self {
      id: self.id,
      sk: self.sk.clone(),
    }
  }
}

impl<S: BlsSchemeId + BlsScheme> BlsSkShare<S> {
  /// Construct a secret key share from an ID and a secret key.
  pub fn new(id: Hash256, sk: BlsSecretKey<S>) -> Self {
    Self { id, sk }
  }

  /// Participant identifier (32-byte hash).
  pub fn id(&self) -> &Hash256 {
    &self.id
  }

  /// Sign a message, producing a signature share.
  ///
  /// # Errors
  ///
  /// Returns `InvalidMessageLength` for Chia when `msg` is not
  /// exactly 32 bytes.
  pub fn sign(&self, msg: &[u8]) -> Result<BlsSigShare<S>, BlsError> {
    Ok(BlsSigShare {
      id: self.id,
      sig: self.sk.sign(msg)?,
    })
  }

  /// The underlying secret key.
  pub fn secret_key(&self) -> &BlsSecretKey<S> {
    &self.sk
  }
}

impl<S: BlsSchemeId + BlsScheme> Debug for BlsSkShare<S> {
  fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
    write!(f, "BlsSkShare(id={:?})", self.id)
  }
}

/// Signature share from one threshold participant.
pub struct BlsSigShare<S: BlsSchemeId + BlsScheme> {
  id: Hash256,
  sig: BlsSignature<S>,
}

impl<S: BlsSchemeId + BlsScheme> Clone for BlsSigShare<S> {
  fn clone(&self) -> Self {
    Self {
      id: self.id,
      sig: self.sig.clone(),
    }
  }
}

impl<S: BlsSchemeId + BlsScheme> BlsSigShare<S> {
  /// Construct a signature share from an ID and a signature.
  pub fn new(id: Hash256, sig: BlsSignature<S>) -> Self {
    Self { id, sig }
  }

  /// Participant identifier (32-byte hash).
  pub fn id(&self) -> &Hash256 {
    &self.id
  }

  /// The underlying signature.
  pub fn signature(&self) -> &BlsSignature<S> {
    &self.sig
  }
}

impl<S: BlsSchemeId + BlsScheme> Debug for BlsSigShare<S> {
  fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
    write!(f, "BlsSigShare(id={:?})", self.id)
  }
}

impl<S: BlsSchemeId + BlsScheme> BlsSecretKey<S> {
  /// Split this secret key into shares for the given participant
  /// IDs, requiring `threshold` shares to recover.
  ///
  /// # Errors
  ///
  /// Returns `ThresholdTooLarge` if `threshold > ids.len()` or
  /// either is zero, `InvalidShareId` if an id reduces to zero in
  /// the scalar field, or `DuplicateShareId` if two ids collide
  /// after reduction.
  pub fn split(
    &self,
    threshold: usize,
    ids: &[Hash256],
    rng: &mut impl CryptoRngCore,
  ) -> Result<Vec<BlsSkShare<S>>, BlsError> {
    if threshold == 0 || ids.is_empty() || threshold > ids.len() {
      return Err(BlsError::ThresholdTooLarge);
    }

    // An id congruent to 0 mod r would make the share equal the
    // master key (the polynomial's constant term).
    let id_refs: Vec<&Hash256> = ids.iter().collect();
    scheme_ops::reduce_share_ids(&id_refs)?;

    let raw =
      scheme_ops::generate_shares(&self.to_bytes(), threshold, ids, rng).map_err(|()| BlsError::InvalidSecretKey)?;

    raw
      .into_iter()
      .map(|(id, bytes)| {
        let share_sk = BlsSecretKey::<S>::from_bytes(&bytes).map_err(|_| BlsError::InvalidSecretKey)?;
        Ok(BlsSkShare { id, sk: share_sk })
      })
      .collect()
  }
}

impl<S: BlsSchemeId + BlsScheme> BlsPublicKey<S> {
  /// Derive a public key share by evaluating the master public
  /// key polynomial at the given participant id.
  pub fn derive_share(master_pks: &[&Self], id: &Hash256) -> Result<Self, BlsError> {
    let inner_refs: Vec<&S::InnerPk> = master_pks.iter().map(|pk| &pk.0).collect();
    S::derive_pk_share(&inner_refs, id).map(Self::from_inner)
  }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "test code")]
mod tests {
  use crate::bls::scheme_ops::BlsScheme;
  use crate::bls::tests::{
    assert_insufficient_shares_rejected, assert_invalid_threshold_rejected, assert_threshold_roundtrip,
  };
  use crate::bls::{BlsPublicKey, BlsScChia, BlsScIetf, BlsSchemeId, BlsSecretKey};
  use crate::prelude::*;
  use crate::tests::*;

  use dash_dev::load_corpus_json;
  use dash_num::Hash256;
  use hex_conservative::DisplayHex;
  use hex_literal::hex;
  use rand_core::OsRng;
  use rstest::*;

  /// BLS12-381 scalar field order r, big-endian.
  const GROUP_ORDER: [u8; 32] = hex!(
    "73eda753299d7d483339d80809a1d805"
    "53bda402fffe5bfeffffffff00000001"
  );

  #[rstest]
  #[case::chia(assert_threshold_roundtrip::<BlsScChia>)]
  #[case::ietf(assert_threshold_roundtrip::<BlsScIetf>)]
  fn threshold_split_recover(#[case] assertion: fn()) {
    assertion();
  }

  fn assert_zero_reducing_ids_rejected<S: BlsSchemeId + BlsScheme>() {
    let sk = BlsSecretKey::<S>::generate(&SEED_0).unwrap();
    let mut ids = sequential_ids(3);

    // The null id evaluates the polynomial at zero.
    ids[1] = Hash256::from([0u8; 32]);
    assert_eq!(
      sk.split(2, &ids, &mut OsRng).unwrap_err(),
      crate::bls::BlsError::InvalidShareId
    );

    // An id equal to the group order reduces to zero mod r, which
    // would make the share equal the master secret key.
    ids[1] = Hash256::from(GROUP_ORDER);
    assert_eq!(
      sk.split(2, &ids, &mut OsRng).unwrap_err(),
      crate::bls::BlsError::InvalidShareId
    );
  }

  #[rstest]
  #[case::chia(assert_zero_reducing_ids_rejected::<BlsScChia>)]
  #[case::ietf(assert_zero_reducing_ids_rejected::<BlsScIetf>)]
  fn split_rejects_zero_reducing_ids(#[case] assertion: fn()) {
    assertion();
  }

  fn assert_congruent_ids_rejected<S: BlsSchemeId + BlsScheme>() {
    let sk = BlsSecretKey::<S>::generate(&SEED_0).unwrap();

    // 1 and r+1 are distinct hashes but the same scalar mod r; a
    // raw-byte duplicate check misses them and interpolation
    // would divide by zero.
    let mut one = [0u8; 32];
    one[31] = 1;
    let mut order_plus_one = GROUP_ORDER;
    order_plus_one[31] = 2;
    let ids = [Hash256::from(one), Hash256::from(order_plus_one)];

    assert_eq!(
      sk.split(2, &ids, &mut OsRng).unwrap_err(),
      crate::bls::BlsError::DuplicateShareId
    );
  }

  #[rstest]
  #[case::chia(assert_congruent_ids_rejected::<BlsScChia>)]
  #[case::ietf(assert_congruent_ids_rejected::<BlsScIetf>)]
  fn split_rejects_ids_congruent_mod_order(#[case] assertion: fn()) {
    assertion();
  }

  fn assert_short_vvec_rejected<S: BlsSchemeId + BlsScheme>() {
    let pk = BlsSecretKey::<S>::generate(&SEED_0).unwrap().public_key();
    let id = sequential_ids(1)[0];
    assert_eq!(
      BlsPublicKey::<S>::derive_share(&[&pk], &id).unwrap_err(),
      crate::bls::BlsError::InvalidVerificationVector
    );
  }

  #[rstest]
  #[case::chia(assert_short_vvec_rejected::<BlsScChia>)]
  #[case::ietf(assert_short_vvec_rejected::<BlsScIetf>)]
  fn derive_share_rejects_short_verification_vector(#[case] assertion: fn()) {
    assertion();
  }

  #[rstest]
  #[case::chia(assert_insufficient_shares_rejected::<BlsScChia>)]
  #[case::ietf(assert_insufficient_shares_rejected::<BlsScIetf>)]
  fn threshold_insufficient_shares(#[case] assertion: fn()) {
    assertion();
  }

  #[rstest]
  #[case::chia_zero(assert_invalid_threshold_rejected::<BlsScChia>, 0, 5)]
  #[case::chia_empty(assert_invalid_threshold_rejected::<BlsScChia>, 1, 0)]
  #[case::chia_above_total(assert_invalid_threshold_rejected::<BlsScChia>, 6, 5)]
  #[case::ietf_zero(assert_invalid_threshold_rejected::<BlsScIetf>, 0, 5)]
  #[case::ietf_empty(assert_invalid_threshold_rejected::<BlsScIetf>, 1, 0)]
  #[case::ietf_above_total(assert_invalid_threshold_rejected::<BlsScIetf>, 6, 5)]
  fn threshold_invalid_params(#[case] assertion: fn(usize, usize), #[case] threshold: usize, #[case] total: usize) {
    assertion(threshold, total);
  }

  fn assert_llmq_contribute_vvec<S: BlsSchemeId + BlsScheme>(corpus: &str) {
    let f = load_corpus_json(env!("CARGO_MANIFEST_DIR"), corpus);

    for c in f["contribute"].as_array().unwrap() {
      let vvec: Vec<&str> = c["vvec"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();

      for pk_hex in &vvec {
        assert!(BlsPublicKey::<S>::from_bytes(&hex_to_48(pk_hex)).is_ok());
      }
    }
  }

  #[rstest]
  #[case::chia("bls_chia_llmq_100", assert_llmq_contribute_vvec::<BlsScChia>)]
  #[case::ietf("bls_ietf_llmq_100", assert_llmq_contribute_vvec::<BlsScIetf>)]
  fn llmq_contribute_vvec(#[case] corpus: &str, #[case] assertion: fn(&str)) {
    assertion(corpus);
  }

  fn assert_llmq_contribute_sk_shares<S: BlsSchemeId + BlsScheme>(corpus: &str) {
    let f = load_corpus_json(env!("CARGO_MANIFEST_DIR"), corpus);
    let n = f["inputs"]["n"].as_u64().unwrap() as usize;

    for c in f["contribute"].as_array().unwrap() {
      let shares = c["sk_shares"].as_array().unwrap();
      assert_eq!(shares.len(), n);
      for s in shares {
        assert!(BlsSecretKey::<S>::from_bytes(&hex_to_32(s.as_str().unwrap())).is_ok());
      }
    }
  }

  #[rstest]
  #[case::chia("bls_chia_llmq_100", assert_llmq_contribute_sk_shares::<BlsScChia>)]
  #[case::ietf("bls_ietf_llmq_100", assert_llmq_contribute_sk_shares::<BlsScIetf>)]
  fn llmq_contribute_sk_shares(#[case] corpus: &str, #[case] assertion: fn(&str)) {
    assertion(corpus);
  }

  fn assert_llmq_verify_contributions<S: BlsSchemeId + BlsScheme>(corpus: &str) {
    let f = load_corpus_json(env!("CARGO_MANIFEST_DIR"), corpus);
    let member_ids: Vec<String> = f["inputs"]["member_ids"]
      .as_array()
      .unwrap()
      .iter()
      .map(|v| v.as_str().unwrap().to_string())
      .collect();

    for v in f["verify"].as_array().unwrap() {
      let member_idx = v["member_idx"].as_u64().unwrap() as usize;
      let received_vvecs = v["received_vvecs"].as_array().unwrap();
      let received_sks = v["received_sk_contributions"].as_array().unwrap();
      let results = v["verification_results"].as_array().unwrap();

      for (contrib_idx, ((vvec_arr, sk_hex), expected)) in received_vvecs
        .iter()
        .zip(received_sks.iter())
        .zip(results.iter())
        .enumerate()
      {
        let vvec: Vec<BlsPublicKey<S>> = vvec_arr
          .as_array()
          .unwrap()
          .iter()
          .map(|v| BlsPublicKey::<S>::from_bytes(&hex_to_48(v.as_str().unwrap())).unwrap())
          .collect();
        let vvec_refs: Vec<&BlsPublicKey<S>> = vvec.iter().collect();

        let sk_share = BlsSecretKey::<S>::from_bytes(&hex_to_32(sk_hex.as_str().unwrap())).unwrap();
        let pk_from_share = sk_share.public_key();

        let member_id = hash_from_hex(&member_ids[member_idx]);
        let pk_from_vvec = BlsPublicKey::derive_share(&vvec_refs, &member_id).unwrap();

        let matches = pk_from_share.to_bytes() == pk_from_vvec.to_bytes();
        assert_eq!(
          matches,
          expected.as_bool().unwrap(),
          "verification mismatch for member {} from contributor {}",
          member_idx,
          contrib_idx,
        );
      }
    }
  }

  #[rstest]
  #[case::chia("bls_chia_llmq_100", assert_llmq_verify_contributions::<BlsScChia>)]
  #[case::ietf("bls_ietf_llmq_100", assert_llmq_verify_contributions::<BlsScIetf>)]
  fn llmq_verify_contributions(#[case] corpus: &str, #[case] assertion: fn(&str)) {
    assertion(corpus);
  }

  fn assert_llmq_commit_quorum_key<S: BlsSchemeId + BlsScheme>(corpus: &str) {
    let f = load_corpus_json(env!("CARGO_MANIFEST_DIR"), corpus);

    let commits = f["commit"].as_array().unwrap();
    let expected_qpk = commits[0]["quorum_public_key"].as_str().unwrap();

    for c in commits {
      assert_eq!(
        c["quorum_public_key"].as_str().unwrap(),
        expected_qpk,
        "quorum pk disagreement at member {}",
        c["member_idx"],
      );
      let qvvec = c["quorum_vvec"].as_array().unwrap();
      assert_eq!(qvvec[0].as_str().unwrap(), expected_qpk);
    }

    let contributions = f["contribute"].as_array().unwrap();
    let member_pks: Vec<BlsPublicKey<S>> = contributions
      .iter()
      .map(|c| BlsPublicKey::<S>::from_bytes(&hex_to_48(c["vvec"][0].as_str().unwrap())).unwrap())
      .collect();
    let pk_refs: Vec<&BlsPublicKey<S>> = member_pks.iter().collect();
    let agg_pk = BlsPublicKey::aggregate(&pk_refs).unwrap();
    assert_eq!(agg_pk.to_bytes().to_lower_hex_string(), expected_qpk);
  }

  #[rstest]
  #[case::chia("bls_chia_llmq_100", assert_llmq_commit_quorum_key::<BlsScChia>)]
  #[case::ietf("bls_ietf_llmq_100", assert_llmq_commit_quorum_key::<BlsScIetf>)]
  fn llmq_commit_quorum_key(#[case] corpus: &str, #[case] assertion: fn(&str)) {
    assertion(corpus);
  }

  fn assert_llmq_commit_sk_share<S: BlsSchemeId + BlsScheme>(corpus: &str) {
    let f = load_corpus_json(env!("CARGO_MANIFEST_DIR"), corpus);

    for (member_idx, c) in f["commit"].as_array().unwrap().iter().enumerate() {
      let expected_share = c["sk_share"].as_str().unwrap();

      let mut received: Vec<BlsSecretKey<S>> = Vec::new();
      for contrib in f["contribute"].as_array().unwrap() {
        let sk_hex = contrib["sk_shares"][member_idx].as_str().unwrap();
        received.push(BlsSecretKey::<S>::from_bytes(&hex_to_32(sk_hex)).unwrap());
      }

      let refs: Vec<&BlsSecretKey<S>> = received.iter().collect();
      let agg = BlsSecretKey::aggregate(&refs).unwrap();
      assert_eq!(
        agg.to_bytes().to_lower_hex_string(),
        expected_share,
        "sk_share mismatch for member {}",
        member_idx,
      );
    }
  }

  #[rstest]
  #[case::chia("bls_chia_llmq_100", assert_llmq_commit_sk_share::<BlsScChia>)]
  #[case::ietf("bls_ietf_llmq_100", assert_llmq_commit_sk_share::<BlsScIetf>)]
  fn llmq_commit_sk_share(#[case] corpus: &str, #[case] assertion: fn(&str)) {
    assertion(corpus);
  }

  fn assert_llmq_commit_sig<S: BlsSchemeId + BlsScheme>(corpus: &str, hash_field: &str, label: &str) {
    let f = load_corpus_json(env!("CARGO_MANIFEST_DIR"), corpus);

    for c in f["commit"].as_array().unwrap() {
      let sk_share = BlsSecretKey::<S>::from_bytes(&hex_to_32(c["sk_share"].as_str().unwrap())).unwrap();
      let msg = hex_to_32(c[hash_field].as_str().unwrap());

      let sig = sk_share.sign(&msg).unwrap();
      let pk = sk_share.public_key();
      assert!(
        sig.verify(&msg, &pk).is_ok(),
        "{} failed self-verification at member {}",
        label,
        c["member_idx"],
      );
    }
  }

  #[rstest]
  #[case::chia_member(
    "bls_chia_llmq_100",
    assert_llmq_commit_sig::<BlsScChia>,
    "commitment_hash",
    "member_sig",
  )]
  #[case::chia_quorum(
    "bls_chia_llmq_100",
    assert_llmq_commit_sig::<BlsScChia>,
    "quorum_hash",
    "quorum_sig_share",
  )]
  #[case::ietf_member(
    "bls_ietf_llmq_100",
    assert_llmq_commit_sig::<BlsScIetf>,
    "commitment_hash",
    "member_sig",
  )]
  #[case::ietf_quorum(
    "bls_ietf_llmq_100",
    assert_llmq_commit_sig::<BlsScIetf>,
    "quorum_hash",
    "quorum_sig_share",
  )]
  fn llmq_commit_sig(
    #[case] corpus: &str,
    #[case] assertion: fn(&str, &str, &str),
    #[case] hash_field: &str,
    #[case] label: &str,
  ) {
    assertion(corpus, hash_field, label);
  }
}
