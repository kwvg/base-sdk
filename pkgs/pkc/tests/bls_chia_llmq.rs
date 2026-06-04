//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! End-to-end quorum DKG validation for legacy BLS.

#![expect(clippy::unwrap_used, reason = "test code")]
#![expect(clippy::panic, reason = "test code")]

mod common;

use dash_pkc::bls_chia::{aggregate_pk, aggregate_sig, threshold, PublicKey, SecretKey, Signature};
use dash_pkc::Hash256;
use hex_conservative::DisplayHex;

#[test]
fn llmq_contribute_vvec() {
  let f = common::load("bls_chia_llmq_100");

  for c in f["contribute"].as_array().unwrap() {
    let vvec: Vec<&str> = c["vvec"]
      .as_array()
      .unwrap()
      .iter()
      .map(|v| v.as_str().unwrap())
      .collect();

    for pk_hex in &vvec {
      assert!(PublicKey::from_bytes(&common::hex_to_48(pk_hex)).is_ok());
    }
  }
}

#[test]
fn llmq_contribute_sk_shares() {
  let f = common::load("bls_chia_llmq_100");
  let n = f["inputs"]["n"].as_u64().unwrap() as usize;

  for c in f["contribute"].as_array().unwrap() {
    let shares = c["sk_shares"].as_array().unwrap();
    assert_eq!(shares.len(), n);
    for s in shares {
      assert!(SecretKey::from_bytes(&common::hex_to_32(s.as_str().unwrap())).is_ok());
    }
  }
}

#[test]
fn llmq_verify_contributions() {
  let f = common::load("bls_chia_llmq_100");
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
      let vvec: Vec<PublicKey> = vvec_arr
        .as_array()
        .unwrap()
        .iter()
        .map(|v| PublicKey::from_bytes(&common::hex_to_48(v.as_str().unwrap())).unwrap())
        .collect();
      let vvec_refs: Vec<&PublicKey> = vvec.iter().collect();

      let sk_share = SecretKey::from_bytes(&common::hex_to_32(sk_hex.as_str().unwrap())).unwrap();
      let pk_from_share = sk_share.public_key();

      let member_id = common::hash_from_hex(&member_ids[member_idx]);
      let pk_from_vvec = threshold::derive_pk_share(&vvec_refs, &member_id).unwrap();

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

#[test]
fn llmq_commit_quorum_key() {
  let f = common::load("bls_chia_llmq_100");

  let commits = f["commit"].as_array().unwrap();
  let expected_qpk = commits[0]["quorum_public_key"].as_str().unwrap();

  for c in commits {
    assert_eq!(c["quorum_public_key"].as_str().unwrap(), expected_qpk);
    let qvvec = c["quorum_vvec"].as_array().unwrap();
    assert_eq!(qvvec[0].as_str().unwrap(), expected_qpk);
  }

  // Reconstruct by aggregating each member's vvec[0].
  let contributions = f["contribute"].as_array().unwrap();
  let member_pks: Vec<PublicKey> = contributions
    .iter()
    .map(|c| PublicKey::from_bytes(&common::hex_to_48(c["vvec"][0].as_str().unwrap())).unwrap())
    .collect();
  let pk_refs: Vec<&PublicKey> = member_pks.iter().collect();
  let agg_pk = aggregate_pk(&pk_refs).unwrap();
  assert_eq!(agg_pk.to_bytes().to_lower_hex_string(), expected_qpk);
}

#[test]
fn llmq_commit_sk_share() {
  let f = common::load("bls_chia_llmq_100");

  for (member_idx, c) in f["commit"].as_array().unwrap().iter().enumerate() {
    let expected_share = c["sk_share"].as_str().unwrap();

    let mut received: Vec<SecretKey> = Vec::new();
    for contrib in f["contribute"].as_array().unwrap() {
      let sk_hex = contrib["sk_shares"][member_idx].as_str().unwrap();
      received.push(SecretKey::from_bytes(&common::hex_to_32(sk_hex)).unwrap());
    }

    let refs: Vec<&SecretKey> = received.iter().collect();
    let agg = dash_pkc::bls_chia::aggregate_sk(&refs).unwrap();
    assert_eq!(agg.to_bytes().to_lower_hex_string(), expected_share);
  }
}

#[test]
fn llmq_commit_member_sig() {
  let f = common::load("bls_chia_llmq_100");

  for c in f["commit"].as_array().unwrap() {
    let sk_share = SecretKey::from_bytes(&common::hex_to_32(c["sk_share"].as_str().unwrap())).unwrap();
    let commitment_hash = common::hex_to_32(c["commitment_hash"].as_str().unwrap());

    // Sign and self-verify.
    let sig = sk_share.sign(&commitment_hash);
    let pk = sk_share.public_key();
    assert!(
      sig.verify(&commitment_hash, &pk).is_ok(),
      "member_sig failed self-verification at member {}",
      c["member_idx"],
    );
  }
}

#[test]
fn llmq_commit_quorum_sig_share() {
  let f = common::load("bls_chia_llmq_100");

  for c in f["commit"].as_array().unwrap() {
    let sk_share = SecretKey::from_bytes(&common::hex_to_32(c["sk_share"].as_str().unwrap())).unwrap();
    let quorum_hash = common::hex_to_32(c["quorum_hash"].as_str().unwrap());

    // Sign and self-verify.
    let sig = sk_share.sign(&quorum_hash);
    let pk = sk_share.public_key();
    assert!(
      sig.verify(&quorum_hash, &pk).is_ok(),
      "quorum_sig_share failed self-verification at member {}",
      c["member_idx"],
    );
  }
}

#[test]
fn llmq_finalize_recover_quorum_sig() {
  let f = common::load("bls_chia_llmq_100");
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

  let quorum_hash = common::hex_to_32(fin["quorum_hash"].as_str().unwrap());

  // signer_ids are internal byte order; byte-reverse to
  // match the display-order member_ids.
  let sig_shares: Vec<threshold::SignatureShare> = signer_ids
    .iter()
    .map(|sid| {
      let sid_bytes = common::hex_to_32(sid);
      let sid_display = sid_bytes
        .iter()
        .copied()
        .rev()
        .collect::<Vec<u8>>()
        .to_lower_hex_string();
      let idx = member_ids.iter().position(|m| *m == sid_display).unwrap();
      let sk = SecretKey::from_bytes(&common::hex_to_32(commits[idx]["sk_share"].as_str().unwrap())).unwrap();
      let member_id = common::hash_from_hex(&sid_display);
      let sk_share = threshold::SecretKeyShare::new(member_id, sk);
      sk_share.sign(&quorum_hash)
    })
    .collect();

  let share_refs: Vec<&threshold::SignatureShare> = sig_shares.iter().collect();
  let recovered = threshold::recover_sig(&share_refs).unwrap();

  let quorum_pk = PublicKey::from_bytes(&common::hex_to_48(commits[0]["quorum_public_key"].as_str().unwrap())).unwrap();
  assert!(
    recovered.verify(&quorum_hash, &quorum_pk).is_ok(),
    "recovered quorum sig failed verification"
  );

  // Cross-check: recovery from all members should match.
  let all_ids: Vec<Hash256> = member_ids.iter().map(|mid| common::hash_from_hex(mid)).collect();
  let all_shares: Vec<threshold::SignatureShare> = commits
    .iter()
    .zip(all_ids.iter())
    .map(|(c, id)| {
      let sk = SecretKey::from_bytes(&common::hex_to_32(c["sk_share"].as_str().unwrap())).unwrap();
      let sk_share = threshold::SecretKeyShare::new(*id, sk);
      sk_share.sign(&quorum_hash)
    })
    .collect();
  let all_refs: Vec<&threshold::SignatureShare> = all_shares.iter().collect();
  let recovered_all = threshold::recover_sig(&all_refs).unwrap();
  assert_eq!(
    recovered.to_bytes(),
    recovered_all.to_bytes(),
    "recovery from subset and full set differ"
  );
}

#[test]
fn llmq_finalize_aggregated_member_sigs() {
  let f = common::load("bls_chia_llmq_100");
  let commits = f["commit"].as_array().unwrap();

  // Re-sign the commitment hash with each member's
  // sk_share using our library, then aggregate.
  let commitment_hash = common::hex_to_32(commits[0]["commitment_hash"].as_str().unwrap());

  let member_sigs: Vec<Signature> = commits
    .iter()
    .map(|c| {
      let sk = SecretKey::from_bytes(&common::hex_to_32(c["sk_share"].as_str().unwrap())).unwrap();
      sk.sign(&commitment_hash)
    })
    .collect();
  let sig_refs: Vec<&Signature> = member_sigs.iter().collect();

  let agg_sig = aggregate_sig(&sig_refs).unwrap();

  let member_pks: Vec<PublicKey> = commits
    .iter()
    .map(|c| {
      let sk = SecretKey::from_bytes(&common::hex_to_32(c["sk_share"].as_str().unwrap())).unwrap();
      sk.public_key()
    })
    .collect();
  let pk_refs: Vec<&PublicKey> = member_pks.iter().collect();

  assert!(
    dash_pkc::bls_chia::fast_verify_aggregates(&agg_sig, &commitment_hash, &pk_refs,).is_ok(),
    "aggregated member sigs failed fast_verify"
  );
}
