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
  use crate::bls::{BlsPublicKey, BlsScChia, BlsScIetf, BlsSecretKey, BlsSignature};
  use crate::bls::{BlsSigShare, BlsSkShare};
  use crate::prelude::*;
  use crate::tests::*;

  use dash_dev::load_corpus_json;
  use hex_conservative::DisplayHex;

  type ChiaSk = BlsSecretKey<BlsScChia>;
  type IetfSk = BlsSecretKey<BlsScIetf>;
  type ChiaPk = BlsPublicKey<BlsScChia>;
  type IetfPk = BlsPublicKey<BlsScIetf>;
  type ChiaSig = BlsSignature<BlsScChia>;
  type IetfSig = BlsSignature<BlsScIetf>;

  #[test]
  fn chia_llmq_finalize_recover_quorum_sig() {
    let f = load_corpus_json(env!("CARGO_MANIFEST_DIR"), "bls_chia_llmq_100");
    let fin = &f["finalize"];
    let commits = f["commit"].as_array().unwrap();

    let member_ids: Vec<String> = f["inputs"]["member_ids"]
      .as_array()
      .unwrap()
      .iter()
      .map(|v| v.as_str().unwrap().to_string())
      .collect();

    let signer_ids: Vec<String> = fin["signer_ids"]
      .as_array()
      .unwrap()
      .iter()
      .map(|v| v.as_str().unwrap().to_string())
      .collect();

    let quorum_hash = hex_to_32(fin["quorum_hash"].as_str().unwrap());

    let sig_shares: Vec<BlsSigShare<BlsScChia>> = signer_ids
      .iter()
      .map(|sid| {
        let sid_bytes = hex_to_32(sid);
        let sid_display = sid_bytes
          .iter()
          .copied()
          .rev()
          .collect::<Vec<u8>>()
          .to_lower_hex_string();
        let idx = member_ids.iter().position(|m| *m == sid_display).unwrap();
        let sk = ChiaSk::from_bytes(&hex_to_32(commits[idx]["sk_share"].as_str().unwrap())).unwrap();
        let member_id = hash_from_hex(&sid_display);
        let sk_share = BlsSkShare::new(member_id, sk);
        sk_share.sign(&quorum_hash)
      })
      .collect();

    let share_refs: Vec<&BlsSigShare<BlsScChia>> = sig_shares.iter().collect();
    let recovered = ChiaSig::recover(&share_refs).unwrap();

    let quorum_pk = ChiaPk::from_bytes(&hex_to_48(commits[0]["quorum_public_key"].as_str().unwrap())).unwrap();
    assert!(
      recovered.verify(&quorum_hash, &quorum_pk).is_ok(),
      "recovered quorum sig failed verification"
    );

    let all_ids: Vec<dash_num::Hash256> = member_ids.iter().map(|mid| hash_from_hex(mid)).collect();
    let all_shares: Vec<BlsSigShare<BlsScChia>> = commits
      .iter()
      .zip(all_ids.iter())
      .map(|(c, id)| {
        let sk = ChiaSk::from_bytes(&hex_to_32(c["sk_share"].as_str().unwrap())).unwrap();
        let sk_share = BlsSkShare::new(*id, sk);
        sk_share.sign(&quorum_hash)
      })
      .collect();
    let all_refs: Vec<&BlsSigShare<BlsScChia>> = all_shares.iter().collect();
    let recovered_all = ChiaSig::recover(&all_refs).unwrap();
    assert_eq!(
      recovered.to_bytes(),
      recovered_all.to_bytes(),
      "recovery from subset and full set differ"
    );
  }

  #[test]
  fn chia_llmq_finalize_aggregated_member_sigs() {
    let f = load_corpus_json(env!("CARGO_MANIFEST_DIR"), "bls_chia_llmq_100");
    let commits = f["commit"].as_array().unwrap();

    let commitment_hash = hex_to_32(commits[0]["commitment_hash"].as_str().unwrap());

    let member_sigs: Vec<ChiaSig> = commits
      .iter()
      .map(|c| {
        let sk = ChiaSk::from_bytes(&hex_to_32(c["sk_share"].as_str().unwrap())).unwrap();
        sk.sign(&commitment_hash)
      })
      .collect();
    let sig_refs: Vec<&ChiaSig> = member_sigs.iter().collect();

    let agg_sig = ChiaSig::aggregate(&sig_refs).unwrap();

    let member_pks: Vec<ChiaPk> = commits
      .iter()
      .map(|c| {
        let sk = ChiaSk::from_bytes(&hex_to_32(c["sk_share"].as_str().unwrap())).unwrap();
        sk.public_key()
      })
      .collect();
    let pk_refs: Vec<&ChiaPk> = member_pks.iter().collect();

    assert!(
      agg_sig.fast_verify_aggregates(&commitment_hash, &pk_refs).is_ok(),
      "aggregated member sigs failed fast_verify"
    );
  }

  #[test]
  fn ietf_llmq_finalize_recover_quorum_sig() {
    let f = load_corpus_json(env!("CARGO_MANIFEST_DIR"), "bls_ietf_llmq_100");
    let fin = &f["finalize"];
    let commits = f["commit"].as_array().unwrap();

    let member_ids: Vec<String> = f["inputs"]["member_ids"]
      .as_array()
      .unwrap()
      .iter()
      .map(|v| v.as_str().unwrap().to_string())
      .collect();

    let signer_ids: Vec<String> = fin["signer_ids"]
      .as_array()
      .unwrap()
      .iter()
      .map(|v| v.as_str().unwrap().to_string())
      .collect();

    let quorum_hash = hex_to_32(fin["quorum_hash"].as_str().unwrap());

    let sig_shares: Vec<BlsSigShare<BlsScIetf>> = signer_ids
      .iter()
      .map(|sid| {
        let sid_bytes = hex_to_32(sid);
        let sid_display = sid_bytes
          .iter()
          .copied()
          .rev()
          .collect::<Vec<u8>>()
          .to_lower_hex_string();
        let idx = member_ids.iter().position(|m| *m == sid_display).unwrap();
        let sk = IetfSk::from_bytes(&hex_to_32(commits[idx]["sk_share"].as_str().unwrap())).unwrap();
        let member_id = hash_from_hex(&sid_display);
        let sk_share = BlsSkShare::new(member_id, sk);
        sk_share.sign(&quorum_hash)
      })
      .collect();

    let share_refs: Vec<&BlsSigShare<BlsScIetf>> = sig_shares.iter().collect();
    let recovered = IetfSig::recover(&share_refs).unwrap();

    let quorum_pk = IetfPk::from_bytes(&hex_to_48(commits[0]["quorum_public_key"].as_str().unwrap())).unwrap();
    assert!(
      recovered.verify(&quorum_hash, &quorum_pk).is_ok(),
      "recovered quorum sig failed verification"
    );

    let all_ids: Vec<dash_num::Hash256> = member_ids.iter().map(|mid| hash_from_hex(mid)).collect();
    let all_shares: Vec<BlsSigShare<BlsScIetf>> = commits
      .iter()
      .zip(all_ids.iter())
      .map(|(c, id)| {
        let sk = IetfSk::from_bytes(&hex_to_32(c["sk_share"].as_str().unwrap())).unwrap();
        let sk_share = BlsSkShare::new(*id, sk);
        sk_share.sign(&quorum_hash)
      })
      .collect();
    let all_refs: Vec<&BlsSigShare<BlsScIetf>> = all_shares.iter().collect();
    let recovered_all = IetfSig::recover(&all_refs).unwrap();
    assert_eq!(
      recovered.to_bytes(),
      recovered_all.to_bytes(),
      "recovery from subset and full set differ"
    );
  }

  #[test]
  fn ietf_llmq_finalize_aggregated_member_sigs() {
    let f = load_corpus_json(env!("CARGO_MANIFEST_DIR"), "bls_ietf_llmq_100");
    let commits = f["commit"].as_array().unwrap();

    let commitment_hash = hex_to_32(commits[0]["commitment_hash"].as_str().unwrap());

    let member_sigs: Vec<IetfSig> = commits
      .iter()
      .map(|c| {
        let sk = IetfSk::from_bytes(&hex_to_32(c["sk_share"].as_str().unwrap())).unwrap();
        sk.sign(&commitment_hash)
      })
      .collect();
    let sig_refs: Vec<&IetfSig> = member_sigs.iter().collect();

    let agg_sig = IetfSig::aggregate(&sig_refs).unwrap();

    let member_pks: Vec<IetfPk> = commits
      .iter()
      .map(|c| {
        let sk = IetfSk::from_bytes(&hex_to_32(c["sk_share"].as_str().unwrap())).unwrap();
        sk.public_key()
      })
      .collect();
    let pk_refs: Vec<&IetfPk> = member_pks.iter().collect();

    assert!(
      agg_sig.fast_verify_aggregates(&commitment_hash, &pk_refs).is_ok(),
      "aggregated member sigs failed fast_verify"
    );
  }
}
