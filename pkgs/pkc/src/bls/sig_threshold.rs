//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Threshold signature recovery via Lagrange interpolation.

use super::error::BlsError;
use super::scheme_ops::BlsScheme;
use super::share_ops::BlsSigShare;
use super::sig_basic::BlsSignature;
use super::BlsSchemeId;
use crate::prelude::*;

use dash_num::Hash256;

impl<S: BlsSchemeId + BlsScheme> BlsSignature<S> {
  /// Recover a full signature from threshold signature shares
  /// via Lagrange interpolation in G2.
  ///
  /// # Errors
  ///
  /// Returns `InsufficientShares` if fewer than 2 shares are
  /// provided, or `DuplicateShareId` if any ids repeat.
  pub fn recover(shares: &[&BlsSigShare<S>]) -> Result<Self, BlsError> {
    let ids: Vec<&Hash256> = shares.iter().map(|s| s.id()).collect();
    let sigs: Vec<&S::InnerSig> = shares.iter().map(|s| &s.signature().0).collect();

    S::recover_sig_shares(&ids, &sigs).map(BlsSignature::from_inner)
  }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "test code")]
mod tests {
  use crate::bls::scheme_ops::BlsScheme;
  use crate::bls::{
    BlsPublicKey, BlsScChia, BlsScIetf, BlsSchemeId, BlsSecretKey, BlsSigShare, BlsSignature, BlsSkShare,
  };
  use crate::prelude::*;
  use crate::tests::*;

  use dash_dev::load_corpus_json;
  use hex_conservative::DisplayHex;
  use rstest::rstest;

  fn assert_llmq_finalize_recover_quorum_sig<S: BlsSchemeId + BlsScheme>(corpus: &str) {
    let f = load_corpus_json(env!("CARGO_MANIFEST_DIR"), corpus);
    let fin = &f["finalize"];
    let commits = f["commit"].as_array().unwrap();
    let member_ids: Vec<String> = f["inputs"]["member_ids"]
      .as_array()
      .unwrap()
      .iter()
      .map(|v| v.as_str().unwrap().to_string())
      .collect();
    let signer_ids = fin["signer_ids"].as_array().unwrap();
    let quorum_hash = hex_to_32(fin["quorum_hash"].as_str().unwrap());

    let sig_shares: Vec<BlsSigShare<S>> = signer_ids
      .iter()
      .map(|sid| {
        let sid_display = hex_to_32(sid.as_str().unwrap())
          .into_iter()
          .rev()
          .collect::<Vec<u8>>()
          .to_lower_hex_string();
        let idx = member_ids.iter().position(|member| member == &sid_display).unwrap();
        let sk = BlsSecretKey::<S>::from_bytes(&hex_to_32(commits[idx]["sk_share"].as_str().unwrap())).unwrap();
        BlsSkShare::new(hash_from_hex(&sid_display), sk).sign(&quorum_hash)
      })
      .collect();

    let share_refs: Vec<&BlsSigShare<S>> = sig_shares.iter().collect();
    let recovered = BlsSignature::<S>::recover(&share_refs).unwrap();
    let quorum_pk =
      BlsPublicKey::<S>::from_bytes(&hex_to_48(commits[0]["quorum_public_key"].as_str().unwrap())).unwrap();
    assert!(
      recovered.verify(&quorum_hash, &quorum_pk).is_ok(),
      "recovered quorum sig failed verification"
    );

    let all_shares: Vec<BlsSigShare<S>> = commits
      .iter()
      .zip(member_ids.iter())
      .map(|(commit, member_id)| {
        let sk = BlsSecretKey::<S>::from_bytes(&hex_to_32(commit["sk_share"].as_str().unwrap())).unwrap();
        BlsSkShare::new(hash_from_hex(member_id), sk).sign(&quorum_hash)
      })
      .collect();
    let all_refs: Vec<&BlsSigShare<S>> = all_shares.iter().collect();
    let recovered_all = BlsSignature::<S>::recover(&all_refs).unwrap();
    assert_eq!(recovered, recovered_all, "recovery from subset and full set differ");
  }

  #[rstest]
  #[case::chia(
    "bls_chia_llmq_100",
    assert_llmq_finalize_recover_quorum_sig::<BlsScChia>,
  )]
  #[case::ietf(
    "bls_ietf_llmq_100",
    assert_llmq_finalize_recover_quorum_sig::<BlsScIetf>,
  )]
  fn llmq_finalize_recover_quorum_sig(#[case] corpus: &str, #[case] assertion: fn(&str)) {
    assertion(corpus);
  }

  fn assert_llmq_finalize_aggregated_member_sigs<S: BlsSchemeId + BlsScheme>(corpus: &str) {
    let f = load_corpus_json(env!("CARGO_MANIFEST_DIR"), corpus);
    let commits = f["commit"].as_array().unwrap();
    let commitment_hash = hex_to_32(commits[0]["commitment_hash"].as_str().unwrap());

    let secret_keys: Vec<BlsSecretKey<S>> = commits
      .iter()
      .map(|commit| BlsSecretKey::from_bytes(&hex_to_32(commit["sk_share"].as_str().unwrap())).unwrap())
      .collect();
    let member_sigs: Vec<BlsSignature<S>> = secret_keys.iter().map(|sk| sk.sign(&commitment_hash)).collect();
    let sig_refs: Vec<&BlsSignature<S>> = member_sigs.iter().collect();
    let aggregate = BlsSignature::aggregate(&sig_refs).unwrap();
    let member_pks: Vec<BlsPublicKey<S>> = secret_keys.iter().map(BlsSecretKey::public_key).collect();
    let pk_refs: Vec<&BlsPublicKey<S>> = member_pks.iter().collect();

    assert!(
      aggregate.fast_verify_aggregates(&commitment_hash, &pk_refs).is_ok(),
      "aggregated member sigs failed fast_verify"
    );
  }

  #[rstest]
  #[case::chia(
    "bls_chia_llmq_100",
    assert_llmq_finalize_aggregated_member_sigs::<BlsScChia>,
  )]
  #[case::ietf(
    "bls_ietf_llmq_100",
    assert_llmq_finalize_aggregated_member_sigs::<BlsScIetf>,
  )]
  fn llmq_finalize_aggregated_member_sigs(#[case] corpus: &str, #[case] assertion: fn(&str)) {
    assertion(corpus);
  }
}
