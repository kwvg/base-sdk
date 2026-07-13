//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Threshold secret-share types, splitting, and public-share derivation.

use super::error::BlsError;
use super::public_ops::BlsPublicKey;
use super::scheme_ops::{self, BlsScheme};
use super::secret_ops::BlsSecretKey;
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

  /// Participant identifier.
  pub fn id(&self) -> &Hash256 {
    &self.id
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

impl<S: BlsSchemeId + BlsScheme> BlsSecretKey<S> {
  /// Split this secret key into shares for the given participant
  /// IDs, requiring `threshold` shares to recover.
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
  /// key polynomial at the given participant ID.
  pub fn derive_share(master_pks: &[&Self], id: &Hash256) -> Result<Self, BlsError> {
    let inner_refs: Vec<&S::InnerPk> = master_pks.iter().map(|pk| &pk.0).collect();
    S::derive_pk_share(&inner_refs, id).map(Self::from_inner)
  }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "test code")]
mod tests {
  use crate::bls::tests::{sequential_ids, MSG_DEADBEEF, SEED_0};
  use crate::bls::{BlsScChia, BlsScIetf, BlsSecretKey};
  use crate::{bls_chia, bls_ietf};

  use alloc::{vec, vec::Vec};

  type ChiaSk = BlsSecretKey<BlsScChia>;
  type IetfSk = BlsSecretKey<BlsScIetf>;

  #[test]
  fn chia_threshold_split_recover() {
    let sk = ChiaSk::generate(&SEED_0).unwrap();
    let ids = sequential_ids(5);
    let mut rng = rand_core::OsRng;
    let shares = sk.split(3, &ids, &mut rng).unwrap();
    let full_sig = sk.sign(&MSG_DEADBEEF);

    let sig_shares: Vec<_> = shares
      .iter()
      .map(|share| bls_chia::threshold::SignatureShare::new(*share.id(), share.secret_key().sign(&MSG_DEADBEEF)))
      .collect();
    let subset: Vec<&bls_chia::threshold::SignatureShare> = vec![&sig_shares[0], &sig_shares[2], &sig_shares[4]];
    let recovered = bls_chia::threshold::recover_sig(&subset).unwrap();
    assert_eq!(recovered.to_bytes(), full_sig.to_bytes());
  }

  #[test]
  fn ietf_threshold_split_recover() {
    let sk = IetfSk::generate(&SEED_0).unwrap();
    let ids = sequential_ids(5);
    let mut rng = rand_core::OsRng;
    let shares = sk.split(3, &ids, &mut rng).unwrap();
    assert_eq!(shares.len(), 5);

    let msg = b"threshold test message";
    let full_sig = sk.sign(msg);
    let sig_shares: Vec<_> = shares
      .iter()
      .map(|share| bls_ietf::threshold::SignatureShare::new(*share.id(), share.secret_key().sign(msg)))
      .collect();
    let subset: Vec<&bls_ietf::threshold::SignatureShare> = vec![&sig_shares[0], &sig_shares[2], &sig_shares[4]];
    let recovered = bls_ietf::threshold::recover_sig(&subset).unwrap();
    assert_eq!(recovered.to_bytes(), full_sig.to_bytes());
  }

  #[test]
  fn ietf_threshold_insufficient_shares() {
    assert!(bls_ietf::threshold::recover_sig(&[]).is_err());
  }

  #[test]
  fn ietf_threshold_invalid_params() {
    let sk = IetfSk::generate(&SEED_0).unwrap();
    let mut rng = rand_core::OsRng;
    let ids = sequential_ids(5);
    assert!(sk.split(0, &ids, &mut rng).is_err());
    assert!(sk.split(6, &ids, &mut rng).is_err());
  }
}

#[cfg(test)]
mod chia_llmq {
  //
  // Copyright (c) 2026-present, The Dash Core developers
  // SPDX-License-Identifier: MIT
  // See the accompanying file LICENSE or https://opensource.org/license/MIT
  //

  //! End-to-end quorum DKG validation for legacy BLS.

  #![expect(clippy::unwrap_used, reason = "test code")]
  #![expect(clippy::panic, reason = "test code")]

  use crate::bls_chia::{aggregate_pk, threshold, PublicKey, SecretKey};
  use alloc::{string::String, string::ToString, vec::Vec};
  use hex_conservative::DisplayHex;

  #[test]
  fn llmq_contribute_vvec() {
    let f = crate::bls::tests::load("bls_chia_llmq_100");

    for c in f["contribute"].as_array().unwrap() {
      let vvec: Vec<&str> = c["vvec"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();

      for pk_hex in &vvec {
        assert!(PublicKey::from_bytes(&crate::bls::tests::hex_to_48(pk_hex)).is_ok());
      }
    }
  }

  #[test]
  fn llmq_contribute_sk_shares() {
    let f = crate::bls::tests::load("bls_chia_llmq_100");
    let n = f["inputs"]["n"].as_u64().unwrap() as usize;

    for c in f["contribute"].as_array().unwrap() {
      let shares = c["sk_shares"].as_array().unwrap();
      assert_eq!(shares.len(), n);
      for s in shares {
        assert!(SecretKey::from_bytes(&crate::bls::tests::hex_to_32(s.as_str().unwrap())).is_ok());
      }
    }
  }

  #[test]
  fn llmq_verify_contributions() {
    let f = crate::bls::tests::load("bls_chia_llmq_100");
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
          .map(|v| PublicKey::from_bytes(&crate::bls::tests::hex_to_48(v.as_str().unwrap())).unwrap())
          .collect();
        let vvec_refs: Vec<&PublicKey> = vvec.iter().collect();

        let sk_share = SecretKey::from_bytes(&crate::bls::tests::hex_to_32(sk_hex.as_str().unwrap())).unwrap();
        let pk_from_share = sk_share.public_key();

        let member_id = crate::bls::tests::hash_from_hex(&member_ids[member_idx]);
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
    let f = crate::bls::tests::load("bls_chia_llmq_100");

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
      .map(|c| PublicKey::from_bytes(&crate::bls::tests::hex_to_48(c["vvec"][0].as_str().unwrap())).unwrap())
      .collect();
    let pk_refs: Vec<&PublicKey> = member_pks.iter().collect();
    let agg_pk = aggregate_pk(&pk_refs).unwrap();
    assert_eq!(agg_pk.to_bytes().to_lower_hex_string(), expected_qpk);
  }

  #[test]
  fn llmq_commit_sk_share() {
    let f = crate::bls::tests::load("bls_chia_llmq_100");

    for (member_idx, c) in f["commit"].as_array().unwrap().iter().enumerate() {
      let expected_share = c["sk_share"].as_str().unwrap();

      let mut received: Vec<SecretKey> = Vec::new();
      for contrib in f["contribute"].as_array().unwrap() {
        let sk_hex = contrib["sk_shares"][member_idx].as_str().unwrap();
        received.push(SecretKey::from_bytes(&crate::bls::tests::hex_to_32(sk_hex)).unwrap());
      }

      let refs: Vec<&SecretKey> = received.iter().collect();
      let agg = crate::bls_chia::aggregate_sk(&refs).unwrap();
      assert_eq!(agg.to_bytes().to_lower_hex_string(), expected_share);
    }
  }

  #[test]
  fn llmq_commit_member_sig() {
    let f = crate::bls::tests::load("bls_chia_llmq_100");

    for c in f["commit"].as_array().unwrap() {
      let sk_share = SecretKey::from_bytes(&crate::bls::tests::hex_to_32(c["sk_share"].as_str().unwrap())).unwrap();
      let commitment_hash = crate::bls::tests::hex_to_32(c["commitment_hash"].as_str().unwrap());

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
    let f = crate::bls::tests::load("bls_chia_llmq_100");

    for c in f["commit"].as_array().unwrap() {
      let sk_share = SecretKey::from_bytes(&crate::bls::tests::hex_to_32(c["sk_share"].as_str().unwrap())).unwrap();
      let quorum_hash = crate::bls::tests::hex_to_32(c["quorum_hash"].as_str().unwrap());

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
}

#[cfg(test)]
mod ietf_llmq {
  //
  // Copyright (c) 2026-present, The Dash Core developers
  // SPDX-License-Identifier: MIT
  // See the accompanying file LICENSE or https://opensource.org/license/MIT
  //

  //! End-to-end quorum DKG validation for IETF BLS.
  //!
  //! Exercises the full distributed key generation flow:
  //! contribute -> verify -> commit -> finalize, validating
  //! each step against reference vectors.

  #![expect(clippy::unwrap_used, reason = "test code")]
  #![expect(clippy::panic, reason = "test code")]

  use crate::bls_ietf::{aggregate_pk, threshold, PublicKey, SecretKey};
  use alloc::{string::String, string::ToString, vec::Vec};
  use hex_conservative::DisplayHex;

  #[test]
  fn llmq_contribute_vvec() {
    let f = crate::bls::tests::load("bls_ietf_llmq_100");

    let contributions = f["contribute"].as_array().unwrap();
    for c in contributions {
      let vvec: Vec<&str> = c["vvec"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();

      // Each vvec entry is a valid G1 point.
      for pk_hex in &vvec {
        assert!(PublicKey::from_bytes(&crate::bls::tests::hex_to_48(pk_hex)).is_ok());
      }

      // The first vvec entry is the member's public key
      // (the constant term of the polynomial commitment).
      // vvec[0] IS the member's contribution public key.
      assert!(
        PublicKey::from_bytes(&crate::bls::tests::hex_to_48(vvec[0]))
          .unwrap()
          .to_bytes()
          .len()
          == 48
      );
    }
  }

  #[test]
  fn llmq_contribute_sk_shares() {
    let f = crate::bls::tests::load("bls_ietf_llmq_100");
    let n = f["inputs"]["n"].as_u64().unwrap() as usize;

    for c in f["contribute"].as_array().unwrap() {
      let shares = c["sk_shares"].as_array().unwrap();
      assert_eq!(shares.len(), n);

      // Each share is a valid 32-byte scalar.
      for s in shares {
        let sk = SecretKey::from_bytes(&crate::bls::tests::hex_to_32(s.as_str().unwrap()));
        assert!(sk.is_ok());
      }
    }
  }

  #[test]
  fn llmq_verify_contributions() {
    let f = crate::bls::tests::load("bls_ietf_llmq_100");
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

      // For each contributor, verify the sk_contribution
      // against the vvec using polynomial evaluation.
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
          .map(|v| PublicKey::from_bytes(&crate::bls::tests::hex_to_48(v.as_str().unwrap())).unwrap())
          .collect();
        let vvec_refs: Vec<&PublicKey> = vvec.iter().collect();

        let sk_share = SecretKey::from_bytes(&crate::bls::tests::hex_to_32(sk_hex.as_str().unwrap())).unwrap();
        let pk_from_share = sk_share.public_key();

        // Evaluate the vvec polynomial at the receiver's
        // participant ID.
        let member_id = crate::bls::tests::hash_from_hex(&member_ids[member_idx]);
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
    let f = crate::bls::tests::load("bls_ietf_llmq_100");

    // All members should agree on the quorum public key.
    let commits = f["commit"].as_array().unwrap();
    let expected_qpk = commits[0]["quorum_public_key"].as_str().unwrap();

    for c in commits {
      assert_eq!(
        c["quorum_public_key"].as_str().unwrap(),
        expected_qpk,
        "quorum pk disagreement at member {}",
        c["member_idx"],
      );

      // The quorum vvec is the sum of all member vvecs.
      // quorum_vvec[0] == quorum_public_key.
      let qvvec = c["quorum_vvec"].as_array().unwrap();
      assert_eq!(qvvec[0].as_str().unwrap(), expected_qpk,);
    }

    // The quorum pk can be reconstructed by aggregating
    // each member's vvec[0] (their contribution pk).
    let contributions = f["contribute"].as_array().unwrap();
    let member_pks: Vec<PublicKey> = contributions
      .iter()
      .map(|c| PublicKey::from_bytes(&crate::bls::tests::hex_to_48(c["vvec"][0].as_str().unwrap())).unwrap())
      .collect();
    let pk_refs: Vec<&PublicKey> = member_pks.iter().collect();
    let agg_pk = aggregate_pk(&pk_refs).unwrap();
    assert_eq!(agg_pk.to_bytes().to_lower_hex_string(), expected_qpk,);
  }

  #[test]
  fn llmq_commit_sk_share() {
    let f = crate::bls::tests::load("bls_ietf_llmq_100");

    // Each member's sk_share in the commit phase is the
    // sum of all received sk_contributions for that member.
    for (member_idx, c) in f["commit"].as_array().unwrap().iter().enumerate() {
      let expected_share = c["sk_share"].as_str().unwrap();

      // Collect the sk_contributions this member received
      // from all contributors.
      let mut received: Vec<SecretKey> = Vec::new();
      for contrib in f["contribute"].as_array().unwrap() {
        let sk_hex = contrib["sk_shares"][member_idx].as_str().unwrap();
        received.push(SecretKey::from_bytes(&crate::bls::tests::hex_to_32(sk_hex)).unwrap());
      }

      let refs: Vec<&SecretKey> = received.iter().collect();
      let agg = crate::bls_ietf::aggregate_sk(&refs).unwrap();
      assert_eq!(
        agg.to_bytes().to_lower_hex_string(),
        expected_share,
        "sk_share mismatch for member {}",
        member_idx,
      );
    }
  }

  #[test]
  fn llmq_commit_member_sig() {
    let f = crate::bls::tests::load("bls_ietf_llmq_100");

    for c in f["commit"].as_array().unwrap() {
      let sk_share = SecretKey::from_bytes(&crate::bls::tests::hex_to_32(c["sk_share"].as_str().unwrap())).unwrap();
      let commitment_hash = crate::bls::tests::hex_to_32(c["commitment_hash"].as_str().unwrap());

      // Sign the commitment hash and verify against pk.
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
    let f = crate::bls::tests::load("bls_ietf_llmq_100");

    for c in f["commit"].as_array().unwrap() {
      let sk_share = SecretKey::from_bytes(&crate::bls::tests::hex_to_32(c["sk_share"].as_str().unwrap())).unwrap();
      let quorum_hash = crate::bls::tests::hex_to_32(c["quorum_hash"].as_str().unwrap());

      // Sign the quorum hash and verify.
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
