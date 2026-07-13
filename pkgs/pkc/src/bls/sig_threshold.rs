//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Threshold-signature tests during the BLS API migration.

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

  use crate::bls_chia::{aggregate_sig, threshold, PublicKey, SecretKey, Signature};
  use alloc::{string::String, string::ToString, vec::Vec};
  use dash_num::Hash256;
  use hex_conservative::DisplayHex;

  #[test]
  fn llmq_finalize_recover_quorum_sig() {
    let f = crate::bls::tests::load("bls_chia_llmq_100");
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

    let quorum_hash = crate::bls::tests::hex_to_32(fin["quorum_hash"].as_str().unwrap());

    // signer_ids are internal byte order; byte-reverse to
    // match the display-order member_ids.
    let sig_shares: Vec<threshold::SignatureShare> = signer_ids
      .iter()
      .map(|sid| {
        let sid_bytes = crate::bls::tests::hex_to_32(sid);
        let sid_display = sid_bytes
          .iter()
          .copied()
          .rev()
          .collect::<Vec<u8>>()
          .to_lower_hex_string();
        let idx = member_ids.iter().position(|m| *m == sid_display).unwrap();
        let sk = SecretKey::from_bytes(&crate::bls::tests::hex_to_32(
          commits[idx]["sk_share"].as_str().unwrap(),
        ))
        .unwrap();
        let member_id = crate::bls::tests::hash_from_hex(&sid_display);
        let sk_share = threshold::SecretKeyShare::new(member_id, sk);
        sk_share.sign(&quorum_hash)
      })
      .collect();

    let share_refs: Vec<&threshold::SignatureShare> = sig_shares.iter().collect();
    let recovered = threshold::recover_sig(&share_refs).unwrap();

    let quorum_pk = PublicKey::from_bytes(&crate::bls::tests::hex_to_48(
      commits[0]["quorum_public_key"].as_str().unwrap(),
    ))
    .unwrap();
    assert!(
      recovered.verify(&quorum_hash, &quorum_pk).is_ok(),
      "recovered quorum sig failed verification"
    );

    // Cross-check: recovery from all members should match.
    let all_ids: Vec<Hash256> = member_ids
      .iter()
      .map(|mid| crate::bls::tests::hash_from_hex(mid))
      .collect();
    let all_shares: Vec<threshold::SignatureShare> = commits
      .iter()
      .zip(all_ids.iter())
      .map(|(c, id)| {
        let sk = SecretKey::from_bytes(&crate::bls::tests::hex_to_32(c["sk_share"].as_str().unwrap())).unwrap();
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
    let f = crate::bls::tests::load("bls_chia_llmq_100");
    let commits = f["commit"].as_array().unwrap();

    // Re-sign the commitment hash with each member's
    // sk_share using our library, then aggregate.
    let commitment_hash = crate::bls::tests::hex_to_32(commits[0]["commitment_hash"].as_str().unwrap());

    let member_sigs: Vec<Signature> = commits
      .iter()
      .map(|c| {
        let sk = SecretKey::from_bytes(&crate::bls::tests::hex_to_32(c["sk_share"].as_str().unwrap())).unwrap();
        sk.sign(&commitment_hash)
      })
      .collect();
    let sig_refs: Vec<&Signature> = member_sigs.iter().collect();

    let agg_sig = aggregate_sig(&sig_refs).unwrap();

    let member_pks: Vec<PublicKey> = commits
      .iter()
      .map(|c| {
        let sk = SecretKey::from_bytes(&crate::bls::tests::hex_to_32(c["sk_share"].as_str().unwrap())).unwrap();
        sk.public_key()
      })
      .collect();
    let pk_refs: Vec<&PublicKey> = member_pks.iter().collect();

    assert!(
      crate::bls_chia::fast_verify_aggregates(&agg_sig, &commitment_hash, &pk_refs,).is_ok(),
      "aggregated member sigs failed fast_verify"
    );
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

  use crate::bls_ietf::{aggregate_sig, threshold, PublicKey, SecretKey, Signature};
  use alloc::{string::String, string::ToString, vec::Vec};
  use dash_num::Hash256;
  use hex_conservative::DisplayHex;

  #[test]
  fn llmq_finalize_recover_quorum_sig() {
    let f = crate::bls::tests::load("bls_ietf_llmq_100");
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

    let quorum_hash = crate::bls::tests::hex_to_32(fin["quorum_hash"].as_str().unwrap());

    // signer_ids are in internal byte order; member_ids
    // are in display (reversed) order. We need to map
    // signer_ids back to member indices and use
    // Hash256::from_hex (display order) for the ID.
    let sig_shares: Vec<threshold::SignatureShare> = signer_ids
      .iter()
      .map(|sid| {
        // sid is internal byte order; byte-reverse to get
        // the display hex that matches member_ids.
        let sid_bytes = crate::bls::tests::hex_to_32(sid);
        let sid_display = sid_bytes
          .iter()
          .copied()
          .rev()
          .collect::<Vec<u8>>()
          .to_lower_hex_string();
        let idx = member_ids.iter().position(|m| *m == sid_display).unwrap();
        let sk = SecretKey::from_bytes(&crate::bls::tests::hex_to_32(
          commits[idx]["sk_share"].as_str().unwrap(),
        ))
        .unwrap();
        let member_id = crate::bls::tests::hash_from_hex(&sid_display);
        let sk_share = threshold::SecretKeyShare::new(member_id, sk);
        sk_share.sign(&quorum_hash)
      })
      .collect();

    let share_refs: Vec<&threshold::SignatureShare> = sig_shares.iter().collect();
    let recovered = threshold::recover_sig(&share_refs).unwrap();

    // Verify the recovered signature against the quorum pk.
    let quorum_pk = PublicKey::from_bytes(&crate::bls::tests::hex_to_48(
      commits[0]["quorum_public_key"].as_str().unwrap(),
    ))
    .unwrap();
    assert!(
      recovered.verify(&quorum_hash, &quorum_pk).is_ok(),
      "recovered quorum sig failed verification"
    );

    // Cross-check: recovery from all members should match.
    let all_ids: Vec<Hash256> = member_ids
      .iter()
      .map(|mid| crate::bls::tests::hash_from_hex(mid))
      .collect();
    let all_shares: Vec<threshold::SignatureShare> = commits
      .iter()
      .zip(all_ids.iter())
      .map(|(c, id)| {
        let sk = SecretKey::from_bytes(&crate::bls::tests::hex_to_32(c["sk_share"].as_str().unwrap())).unwrap();
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
    let f = crate::bls::tests::load("bls_ietf_llmq_100");
    let commits = f["commit"].as_array().unwrap();

    // Re-sign the commitment hash with each member's
    // sk_share using our library, then aggregate.
    let commitment_hash = crate::bls::tests::hex_to_32(commits[0]["commitment_hash"].as_str().unwrap());

    let member_sigs: Vec<Signature> = commits
      .iter()
      .map(|c| {
        let sk = SecretKey::from_bytes(&crate::bls::tests::hex_to_32(c["sk_share"].as_str().unwrap())).unwrap();
        sk.sign(&commitment_hash)
      })
      .collect();
    let sig_refs: Vec<&Signature> = member_sigs.iter().collect();

    let agg_sig = aggregate_sig(&sig_refs).unwrap();

    // Verify the aggregated member sig against the
    // commitment hash using each member's public key.
    let member_pks: Vec<PublicKey> = commits
      .iter()
      .map(|c| {
        let sk = SecretKey::from_bytes(&crate::bls::tests::hex_to_32(c["sk_share"].as_str().unwrap())).unwrap();
        sk.public_key()
      })
      .collect();
    let pk_refs: Vec<&PublicKey> = member_pks.iter().collect();

    assert!(
      crate::bls_ietf::fast_verify_aggregates(&agg_sig, &commitment_hash, &pk_refs,).is_ok(),
      "aggregated member sigs failed fast_verify"
    );
  }
}
