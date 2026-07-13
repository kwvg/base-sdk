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

use core::fmt;

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
  pub fn sign(&self, msg: &[u8]) -> BlsSigShare<S> {
    BlsSigShare {
      id: self.id,
      sig: self.sk.sign(msg),
    }
  }

  /// The underlying secret key.
  pub fn secret_key(&self) -> &BlsSecretKey<S> {
    &self.sk
  }
}

impl<S: BlsSchemeId + BlsScheme> fmt::Debug for BlsSkShare<S> {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
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

impl<S: BlsSchemeId + BlsScheme> fmt::Debug for BlsSigShare<S> {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
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
  /// either is zero.
  pub fn split(
    &self,
    threshold: usize,
    ids: &[Hash256],
    rng: &mut impl CryptoRngCore,
  ) -> Result<Vec<BlsSkShare<S>>, BlsError> {
    if threshold == 0 || ids.is_empty() || threshold > ids.len() {
      return Err(BlsError::ThresholdTooLarge);
    }

    for id in ids {
      if id.is_null() {
        return Err(BlsError::ThresholdTooLarge);
      }
    }

    for i in 0..ids.len() {
      for j in (i + 1)..ids.len() {
        if ids[i] == ids[j] {
          return Err(BlsError::DuplicateShareId);
        }
      }
    }

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
  use crate::bls::BlsSigShare;
  use crate::bls::{BlsPublicKey, BlsScChia, BlsScIetf, BlsSecretKey, BlsSignature};
  use crate::prelude::*;
  use crate::tests::*;

  use dash_dev::load_corpus_json;
  use hex_conservative::DisplayHex;
  use rstest::*;

  type ChiaSk = BlsSecretKey<BlsScChia>;
  type IetfSk = BlsSecretKey<BlsScIetf>;
  type ChiaPk = BlsPublicKey<BlsScChia>;
  type IetfPk = BlsPublicKey<BlsScIetf>;
  type ChiaSig = BlsSignature<BlsScChia>;
  type IetfSig = BlsSignature<BlsScIetf>;

  #[rstest]
  fn chia_threshold_split_recover() {
    let sk = ChiaSk::generate(&SEED_0).unwrap();
    let ids = sequential_ids(5);
    let mut rng = rand_core::OsRng;
    let shares = sk.split(3, &ids, &mut rng).unwrap();
    let msg32 = MSG_DEADBEEF;
    let full_sig = sk.sign(&msg32);

    let sig_shares: Vec<_> = shares.iter().map(|s| s.sign(&msg32)).collect();
    let subset: Vec<&BlsSigShare<BlsScChia>> = vec![&sig_shares[0], &sig_shares[2], &sig_shares[4]];
    let recovered = ChiaSig::recover(&subset).unwrap();
    assert_eq!(recovered.to_bytes(), full_sig.to_bytes());
  }

  #[rstest]
  fn ietf_threshold_split_recover() {
    let sk = IetfSk::generate(&SEED_0).unwrap();
    let ids = sequential_ids(5);
    let mut rng = rand_core::OsRng;
    let shares = sk.split(3, &ids, &mut rng).unwrap();
    assert_eq!(shares.len(), 5);

    let msg = b"threshold test message";
    let full_sig = sk.sign(msg);

    let sig_shares: Vec<_> = shares.iter().map(|s| s.sign(msg)).collect();

    let subset: Vec<&BlsSigShare<BlsScIetf>> = vec![&sig_shares[0], &sig_shares[2], &sig_shares[4]];
    let recovered = IetfSig::recover(&subset).unwrap();
    assert_eq!(recovered.to_bytes(), full_sig.to_bytes());
  }

  #[rstest]
  fn ietf_threshold_insufficient_shares() {
    assert!(IetfSig::recover(&[]).is_err());
  }

  #[rstest]
  fn ietf_threshold_invalid_params() {
    let sk = IetfSk::generate(&SEED_0).unwrap();
    let mut rng = rand_core::OsRng;
    let ids = sequential_ids(5);
    assert!(sk.split(0, &ids, &mut rng).is_err());
    let ids6 = sequential_ids(5);
    assert!(sk.split(6, &ids6, &mut rng).is_err());
  }

  #[test]
  fn chia_llmq_contribute_vvec() {
    let f = load_corpus_json(env!("CARGO_MANIFEST_DIR"), "bls_chia_llmq_100");

    for c in f["contribute"].as_array().unwrap() {
      let vvec: Vec<&str> = c["vvec"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();

      for pk_hex in &vvec {
        assert!(ChiaPk::from_bytes(&hex_to_48(pk_hex)).is_ok());
      }
    }
  }

  #[test]
  fn chia_llmq_contribute_sk_shares() {
    let f = load_corpus_json(env!("CARGO_MANIFEST_DIR"), "bls_chia_llmq_100");
    let n = f["inputs"]["n"].as_u64().unwrap() as usize;

    for c in f["contribute"].as_array().unwrap() {
      let shares = c["sk_shares"].as_array().unwrap();
      assert_eq!(shares.len(), n);
      for s in shares {
        assert!(ChiaSk::from_bytes(&hex_to_32(s.as_str().unwrap())).is_ok());
      }
    }
  }

  #[test]
  fn chia_llmq_verify_contributions() {
    let f = load_corpus_json(env!("CARGO_MANIFEST_DIR"), "bls_chia_llmq_100");
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
        let vvec: Vec<ChiaPk> = vvec_arr
          .as_array()
          .unwrap()
          .iter()
          .map(|v| ChiaPk::from_bytes(&hex_to_48(v.as_str().unwrap())).unwrap())
          .collect();
        let vvec_refs: Vec<&ChiaPk> = vvec.iter().collect();

        let sk_share = ChiaSk::from_bytes(&hex_to_32(sk_hex.as_str().unwrap())).unwrap();
        let pk_from_share = sk_share.public_key();

        let member_id = hash_from_hex(&member_ids[member_idx]);
        let pk_from_vvec = ChiaPk::derive_share(&vvec_refs, &member_id).unwrap();

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
  fn chia_llmq_commit_quorum_key() {
    let f = load_corpus_json(env!("CARGO_MANIFEST_DIR"), "bls_chia_llmq_100");

    let commits = f["commit"].as_array().unwrap();
    let expected_qpk = commits[0]["quorum_public_key"].as_str().unwrap();

    for c in commits {
      assert_eq!(c["quorum_public_key"].as_str().unwrap(), expected_qpk);
      let qvvec = c["quorum_vvec"].as_array().unwrap();
      assert_eq!(qvvec[0].as_str().unwrap(), expected_qpk);
    }

    let contributions = f["contribute"].as_array().unwrap();
    let member_pks: Vec<ChiaPk> = contributions
      .iter()
      .map(|c| ChiaPk::from_bytes(&hex_to_48(c["vvec"][0].as_str().unwrap())).unwrap())
      .collect();
    let pk_refs: Vec<&ChiaPk> = member_pks.iter().collect();
    let agg_pk = ChiaPk::aggregate(&pk_refs).unwrap();
    assert_eq!(agg_pk.to_bytes().to_lower_hex_string(), expected_qpk);
  }

  #[test]
  fn chia_llmq_commit_sk_share() {
    let f = load_corpus_json(env!("CARGO_MANIFEST_DIR"), "bls_chia_llmq_100");

    for (member_idx, c) in f["commit"].as_array().unwrap().iter().enumerate() {
      let expected_share = c["sk_share"].as_str().unwrap();

      let mut received: Vec<ChiaSk> = Vec::new();
      for contrib in f["contribute"].as_array().unwrap() {
        let sk_hex = contrib["sk_shares"][member_idx].as_str().unwrap();
        received.push(ChiaSk::from_bytes(&hex_to_32(sk_hex)).unwrap());
      }

      let refs: Vec<&ChiaSk> = received.iter().collect();
      let agg = ChiaSk::aggregate(&refs).unwrap();
      assert_eq!(agg.to_bytes().to_lower_hex_string(), expected_share);
    }
  }

  #[test]
  fn chia_llmq_commit_member_sig() {
    let f = load_corpus_json(env!("CARGO_MANIFEST_DIR"), "bls_chia_llmq_100");

    for c in f["commit"].as_array().unwrap() {
      let sk_share = ChiaSk::from_bytes(&hex_to_32(c["sk_share"].as_str().unwrap())).unwrap();
      let commitment_hash = hex_to_32(c["commitment_hash"].as_str().unwrap());

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
  fn chia_llmq_commit_quorum_sig_share() {
    let f = load_corpus_json(env!("CARGO_MANIFEST_DIR"), "bls_chia_llmq_100");

    for c in f["commit"].as_array().unwrap() {
      let sk_share = ChiaSk::from_bytes(&hex_to_32(c["sk_share"].as_str().unwrap())).unwrap();
      let quorum_hash = hex_to_32(c["quorum_hash"].as_str().unwrap());

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
  fn ietf_llmq_contribute_vvec() {
    let f = load_corpus_json(env!("CARGO_MANIFEST_DIR"), "bls_ietf_llmq_100");

    let contributions = f["contribute"].as_array().unwrap();
    for c in contributions {
      let vvec: Vec<&str> = c["vvec"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();

      for pk_hex in &vvec {
        assert!(IetfPk::from_bytes(&hex_to_48(pk_hex)).is_ok());
      }

      assert!(IetfPk::from_bytes(&hex_to_48(vvec[0])).unwrap().to_bytes().len() == 48);
    }
  }

  #[test]
  fn ietf_llmq_contribute_sk_shares() {
    let f = load_corpus_json(env!("CARGO_MANIFEST_DIR"), "bls_ietf_llmq_100");
    let n = f["inputs"]["n"].as_u64().unwrap() as usize;

    for c in f["contribute"].as_array().unwrap() {
      let shares = c["sk_shares"].as_array().unwrap();
      assert_eq!(shares.len(), n);

      for s in shares {
        let sk = IetfSk::from_bytes(&hex_to_32(s.as_str().unwrap()));
        assert!(sk.is_ok());
      }
    }
  }

  #[test]
  fn ietf_llmq_verify_contributions() {
    let f = load_corpus_json(env!("CARGO_MANIFEST_DIR"), "bls_ietf_llmq_100");
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
        let vvec: Vec<IetfPk> = vvec_arr
          .as_array()
          .unwrap()
          .iter()
          .map(|v| IetfPk::from_bytes(&hex_to_48(v.as_str().unwrap())).unwrap())
          .collect();
        let vvec_refs: Vec<&IetfPk> = vvec.iter().collect();

        let sk_share = IetfSk::from_bytes(&hex_to_32(sk_hex.as_str().unwrap())).unwrap();
        let pk_from_share = sk_share.public_key();

        let member_id = hash_from_hex(&member_ids[member_idx]);
        let pk_from_vvec = IetfPk::derive_share(&vvec_refs, &member_id).unwrap();

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
  fn ietf_llmq_commit_quorum_key() {
    let f = load_corpus_json(env!("CARGO_MANIFEST_DIR"), "bls_ietf_llmq_100");

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
    let member_pks: Vec<IetfPk> = contributions
      .iter()
      .map(|c| IetfPk::from_bytes(&hex_to_48(c["vvec"][0].as_str().unwrap())).unwrap())
      .collect();
    let pk_refs: Vec<&IetfPk> = member_pks.iter().collect();
    let agg_pk = IetfPk::aggregate(&pk_refs).unwrap();
    assert_eq!(agg_pk.to_bytes().to_lower_hex_string(), expected_qpk);
  }

  #[test]
  fn ietf_llmq_commit_sk_share() {
    let f = load_corpus_json(env!("CARGO_MANIFEST_DIR"), "bls_ietf_llmq_100");

    for (member_idx, c) in f["commit"].as_array().unwrap().iter().enumerate() {
      let expected_share = c["sk_share"].as_str().unwrap();

      let mut received: Vec<IetfSk> = Vec::new();
      for contrib in f["contribute"].as_array().unwrap() {
        let sk_hex = contrib["sk_shares"][member_idx].as_str().unwrap();
        received.push(IetfSk::from_bytes(&hex_to_32(sk_hex)).unwrap());
      }

      let refs: Vec<&IetfSk> = received.iter().collect();
      let agg = IetfSk::aggregate(&refs).unwrap();
      assert_eq!(
        agg.to_bytes().to_lower_hex_string(),
        expected_share,
        "sk_share mismatch for member {}",
        member_idx,
      );
    }
  }

  #[test]
  fn ietf_llmq_commit_member_sig() {
    let f = load_corpus_json(env!("CARGO_MANIFEST_DIR"), "bls_ietf_llmq_100");

    for c in f["commit"].as_array().unwrap() {
      let sk_share = IetfSk::from_bytes(&hex_to_32(c["sk_share"].as_str().unwrap())).unwrap();
      let commitment_hash = hex_to_32(c["commitment_hash"].as_str().unwrap());

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
  fn ietf_llmq_commit_quorum_sig_share() {
    let f = load_corpus_json(env!("CARGO_MANIFEST_DIR"), "bls_ietf_llmq_100");

    for c in f["commit"].as_array().unwrap() {
      let sk_share = IetfSk::from_bytes(&hex_to_32(c["sk_share"].as_str().unwrap())).unwrap();
      let quorum_hash = hex_to_32(c["quorum_hash"].as_str().unwrap());

      let sig = sk_share.sign(&quorum_hash);
      let pk = sk_share.public_key();
      assert!(
        sig.verify(&quorum_hash, &pk).is_ok(),
        "quorum_sig_share failed self-verification at member {}",
        c["member_idx"],
      );
    }
  }
}
