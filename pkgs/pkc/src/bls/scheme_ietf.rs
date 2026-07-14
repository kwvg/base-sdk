//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! IETF-standard BLS scheme: `BlsScheme` implementation.

use super::blst_ffi;
use super::error::BlsError;
use super::scheme_ops::{self, BlsScheme};
use super::schemes::BlsScIetf;
use super::BlsSigId;
use crate::prelude::*;

use blst::min_pk::{AggregatePublicKey, AggregateSignature, PublicKey, SecretKey, Signature};
use blst::{blst_p1_affine, blst_p2_affine, BLST_ERROR};
use dash_num::Hash256;
use zeroize::Zeroize;

// IETF domain separation tags.
pub(crate) const DST_BASIC: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";
pub(crate) const DST_AUG: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_AUG_";
pub(crate) const DST_POP: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";
pub(crate) const DST_POP_PROVE: &[u8] = b"BLS_POP_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";

impl BlsScheme for BlsScIetf {
  type InnerSk = SecretKey;
  type InnerPk = PublicKey;
  type InnerSig = Signature;

  fn generate(ikm: &[u8]) -> Result<Self::InnerSk, BlsError> {
    // key_gen_v3 is the EIP-2333 form dashbls CoreMPL::KeyGen
    // uses (plain keygen salt, OS2IP mod r); the default key_gen
    // is draft v4 and derives different keys from the same seed.
    SecretKey::key_gen_v3(ikm, &[]).map_err(|_| BlsError::InvalidKeyMaterial)
  }

  fn sk_from_bytes(b: &[u8; 32]) -> Result<Self::InnerSk, BlsError> {
    SecretKey::from_bytes(b).map_err(|_| BlsError::InvalidSecretKey)
  }

  fn sk_to_bytes(sk: &Self::InnerSk) -> [u8; 32] {
    sk.to_bytes()
  }

  fn derive_pk(sk: &Self::InnerSk) -> Self::InnerPk {
    sk.sk_to_pk()
  }

  fn pk_from_bytes(b: &[u8; 48]) -> Result<Self::InnerPk, BlsError> {
    // key_validate rejects infinity and non-subgroup points, so
    // every InnerPk in circulation is a valid G1 group element.
    PublicKey::key_validate(b).map_err(|_| BlsError::InvalidPublicKey)
  }

  fn pk_to_bytes(pk: &Self::InnerPk) -> [u8; 48] {
    pk.compress()
  }

  fn pk_to_ietf_bytes(pk: &Self::InnerPk) -> [u8; 48] {
    pk.compress()
  }

  fn sig_from_bytes(b: &[u8; 96]) -> Result<Self::InnerSig, BlsError> {
    // sig_validate rejects infinity and non-subgroup points, so
    // every InnerSig in circulation is a valid G2 group element.
    Signature::sig_validate(b, true).map_err(|_| BlsError::InvalidSignature)
  }

  fn sig_to_bytes(sig: &Self::InnerSig) -> [u8; 96] {
    sig.compress()
  }

  fn sign(sk: &Self::InnerSk, msg: &[u8]) -> Result<Self::InnerSig, BlsError> {
    Ok(sk.sign(msg, DST_BASIC, &[]))
  }

  fn sign_with(sk: &Self::InnerSk, msg: &[u8], scheme: BlsSigId) -> Result<Self::InnerSig, BlsError> {
    let (dst, aug) = match scheme {
      BlsSigId::Basic => (DST_BASIC, Vec::new()),
      // AugSchemeMPL signs pk || msg under the AUG dst.
      BlsSigId::MessageAugmentation => (DST_AUG, sk.sk_to_pk().compress().to_vec()),
      BlsSigId::ProofOfPossession => (DST_POP, Vec::new()),
    };
    Ok(sk.sign(msg, dst, &aug))
  }

  fn verify(sig: &Self::InnerSig, msg: &[u8], pk: &Self::InnerPk) -> Result<(), BlsError> {
    // Signatures and keys are group-checked at parse (and closed
    // under the operations that produce them), so per-verify
    // validation would repeat that work.
    let result = sig.verify(false, msg, DST_BASIC, &[], pk, false);
    if result == BLST_ERROR::BLST_SUCCESS {
      Ok(())
    } else {
      Err(BlsError::VerifyFailed)
    }
  }

  fn verify_with(sig: &Self::InnerSig, msg: &[u8], pk: &Self::InnerPk, scheme: BlsSigId) -> Result<(), BlsError> {
    let (dst, aug) = match scheme {
      BlsSigId::Basic => (DST_BASIC, Vec::new()),
      BlsSigId::MessageAugmentation => (DST_AUG, pk.compress().to_vec()),
      BlsSigId::ProofOfPossession => (DST_POP, Vec::new()),
    };
    let result = sig.verify(false, msg, dst, &aug, pk, false);
    if result == BLST_ERROR::BLST_SUCCESS {
      Ok(())
    } else {
      Err(BlsError::VerifyFailed)
    }
  }

  fn prove_possession(sk: &Self::InnerSk, pk: &Self::InnerPk) -> Result<Self::InnerSig, BlsError> {
    let pk_bytes = pk.compress();
    Ok(sk.sign(&pk_bytes, DST_POP_PROVE, &[]))
  }

  fn verify_possession(pk: &Self::InnerPk, pop: &Self::InnerSig) -> Result<(), BlsError> {
    let pk_bytes = pk.compress();
    let result = pop.verify(false, &pk_bytes, DST_POP_PROVE, &[], pk, false);
    if result == BLST_ERROR::BLST_SUCCESS {
      Ok(())
    } else {
      Err(BlsError::VerifyFailed)
    }
  }

  fn dh_exchange(sk: &Self::InnerSk, peer_pk: &Self::InnerPk) -> Result<Self::InnerPk, BlsError> {
    // Uncompressed serialization round-trips cost an on-curve
    // check only; the compressed form would pay a square root in
    // each direction. The peer key is group-checked at parse and
    // the secret key is a nonzero reduced scalar, so the product
    // is a valid non-infinity group element.
    let ser = peer_pk.serialize();
    let aff = blst_ffi::p1_deserialize(&ser).map_err(|_| BlsError::InvalidPublicKey)?;
    let mut sk_bytes = sk.to_bytes();
    let mut sk_scalar = blst_ffi::scalar_from_bendian(&sk_bytes);
    let out_aff = blst_ffi::p1_mult(&aff, &sk_scalar.b, blst_ffi::FR_BITS);
    sk_bytes.zeroize();
    sk_scalar.zeroize();
    let out_ser = blst_ffi::p1_affine_serialize(&out_aff);
    PublicKey::deserialize(&out_ser).map_err(|_| BlsError::InvalidPublicKey)
  }

  fn aggregate_pk(pks: &[&Self::InnerPk]) -> Result<Self::InnerPk, BlsError> {
    if pks.is_empty() {
      return Err(BlsError::EmptyAggregation);
    }
    // Inputs are subgroup-checked at parse (pk_from_bytes), so
    // per-element validation here would be redundant.
    let agg = AggregatePublicKey::aggregate(pks, false).map_err(|_| BlsError::InvalidPublicKey)?;
    let pk = agg.to_public_key();
    // Keys can cancel to infinity; an infinity aggregate is not a
    // usable public key (Dash Core treats it as invalid).
    if pk.compress()[0] & 0xc0 == 0xc0 {
      return Err(BlsError::InvalidPublicKey);
    }
    Ok(pk)
  }

  fn aggregate_sig(sigs: &[&Self::InnerSig]) -> Result<Self::InnerSig, BlsError> {
    if sigs.is_empty() {
      return Err(BlsError::EmptyAggregation);
    }
    // Inputs are subgroup-checked at parse (sig_from_bytes), so
    // per-element validation here would be redundant.
    let agg = AggregateSignature::aggregate(sigs, false).map_err(|_| BlsError::InvalidSignature)?;
    let sig = agg.to_signature();
    // Signatures can cancel to infinity; an infinity aggregate is
    // not a usable signature (Dash Core treats it as invalid).
    if sig.compress()[0] & 0xc0 == 0xc0 {
      return Err(BlsError::InvalidSignature);
    }
    Ok(sig)
  }

  fn fast_verify_aggregates(sig: &Self::InnerSig, msg: &[u8], pks: &[&Self::InnerPk]) -> Result<(), BlsError> {
    if pks.is_empty() {
      return Err(BlsError::EmptyAggregation);
    }
    let result = sig.fast_aggregate_verify(false, msg, DST_BASIC, pks);
    if result == BLST_ERROR::BLST_SUCCESS {
      Ok(())
    } else {
      Err(BlsError::VerifyFailed)
    }
  }

  fn verify_aggregates(sig: &Self::InnerSig, msgs: &[&[u8]], pks: &[&Self::InnerPk]) -> Result<(), BlsError> {
    if pks.len() != msgs.len() {
      return Err(BlsError::CountMismatch);
    }
    if pks.is_empty() {
      return Err(BlsError::EmptyAggregation);
    }
    // BasicSchemeMPL requires all messages to be distinct; a
    // repeated message would allow signature splitting.
    let mut seen: alloc::collections::BTreeSet<&[u8]> = alloc::collections::BTreeSet::new();
    if !msgs.iter().all(|m| seen.insert(m)) {
      return Err(BlsError::DuplicateMessage);
    }
    let result = sig.aggregate_verify(false, msgs, DST_BASIC, pks, false);
    if result == BLST_ERROR::BLST_SUCCESS {
      Ok(())
    } else {
      Err(BlsError::VerifyFailed)
    }
  }

  fn verify_aggregates_with(
    sig: &Self::InnerSig,
    msgs: &[&[u8]],
    pks: &[&Self::InnerPk],
    scheme: BlsSigId,
  ) -> Result<(), BlsError> {
    match scheme {
      BlsSigId::Basic => Self::verify_aggregates(sig, msgs, pks),
      BlsSigId::MessageAugmentation => {
        if pks.len() != msgs.len() {
          return Err(BlsError::CountMismatch);
        }
        if pks.is_empty() {
          return Err(BlsError::EmptyAggregation);
        }
        // AugSchemeMPL verifies pk_i || msg_i; the pk prefix
        // disambiguates repeated messages, so no distinctness
        // rule applies.
        let aug_msgs: Vec<Vec<u8>> = pks
          .iter()
          .zip(msgs)
          .map(|(pk, msg)| {
            let mut m = Vec::with_capacity(48 + msg.len());
            m.extend_from_slice(&pk.compress());
            m.extend_from_slice(msg);
            m
          })
          .collect();
        let aug_refs: Vec<&[u8]> = aug_msgs.iter().map(|m| m.as_slice()).collect();
        let result = sig.aggregate_verify(false, &aug_refs, DST_AUG, pks, false);
        if result == BLST_ERROR::BLST_SUCCESS {
          Ok(())
        } else {
          Err(BlsError::VerifyFailed)
        }
      }
      BlsSigId::ProofOfPossession => {
        if pks.len() != msgs.len() {
          return Err(BlsError::CountMismatch);
        }
        if pks.is_empty() {
          return Err(BlsError::EmptyAggregation);
        }
        let result = sig.aggregate_verify(false, msgs, DST_POP, pks, false);
        if result == BLST_ERROR::BLST_SUCCESS {
          Ok(())
        } else {
          Err(BlsError::VerifyFailed)
        }
      }
    }
  }

  fn secure_verify_aggregates(sig: &Self::InnerSig, msg: &[u8], pks: &[&Self::InnerPk]) -> Result<(), BlsError> {
    if pks.is_empty() {
      return Err(BlsError::EmptyAggregation);
    }

    // Pair each compressed encoding (the weight-derivation input)
    // with the point we already hold, avoiding a square root per
    // key to re-derive points from compressed bytes.
    let mut sorted: Vec<([u8; 48], blst_p1_affine)> = pks
      .iter()
      .map(|pk| {
        let aff = blst_ffi::p1_deserialize(&pk.serialize()).map_err(|_| BlsError::InvalidPublicKey)?;
        Ok((pk.compress(), aff))
      })
      .collect::<Result<_, BlsError>>()?;
    sorted.sort_by_key(|pair| pair.0);

    let agg_pk_aff = scheme_ops::weighted_g1_aggregate(&sorted)?;
    let agg_pk_ser = blst_ffi::p1_affine_serialize(&agg_pk_aff);
    let agg_pk = PublicKey::deserialize(&agg_pk_ser).map_err(|_| BlsError::InvalidPublicKey)?;
    Self::verify(sig, msg, &agg_pk)
  }

  fn recover_sig_shares(ids: &[&Hash256], sigs: &[&Self::InnerSig]) -> Result<Self::InnerSig, BlsError> {
    // Uncompressed serialization round-trips cost an on-curve
    // check only; the compressed form would pay an Fp2 square
    // root per share and another on the result. Interpolation
    // over subgroup points stays in the subgroup, so the result
    // only needs an infinity check, not a group check.
    let aff_sigs: Vec<blst_p2_affine> = sigs
      .iter()
      .map(|s| blst_ffi::p2_deserialize(&s.serialize()).map_err(|_| BlsError::InvalidSignature))
      .collect::<Result<_, _>>()?;

    let recovered = scheme_ops::recover_sig_shares_affine(ids, &aff_sigs)?;
    if blst_ffi::p2_affine_is_inf(&recovered) {
      return Err(BlsError::InvalidSignature);
    }
    let ser = blst_ffi::p2_affine_serialize(&recovered);
    Signature::deserialize(&ser).map_err(|_| BlsError::InvalidSignature)
  }

  fn derive_pk_share(master_pks: &[&Self::InnerPk], id: &Hash256) -> Result<Self::InnerPk, BlsError> {
    let aff_pks: Vec<blst_p1_affine> = master_pks
      .iter()
      .map(|pk| blst_ffi::p1_deserialize(&pk.serialize()).map_err(|_| BlsError::InvalidPublicKey))
      .collect::<Result<_, _>>()?;

    // The MSM over subgroup points stays in the subgroup, so the
    // result only needs an infinity check, not a group check.
    let result = scheme_ops::derive_pk_share_affine(&aff_pks, id)?;
    if blst_ffi::p1_affine_is_inf(&result) {
      return Err(BlsError::InvalidPublicKey);
    }
    let ser = blst_ffi::p1_affine_serialize(&result);
    PublicKey::deserialize(&ser).map_err(|_| BlsError::InvalidPublicKey)
  }

  fn zeroize_sk(_sk: &mut Self::InnerSk) {
    // blst::min_pk::SecretKey handles zeroization internally.
  }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "test code")]
mod tests {
  use super::*;
  use crate::tests::{SEED_0, SEED_1};

  use hex_literal::hex;
  use rstest::rstest;

  #[rstest]
  fn proof_of_possession_verifies_and_rejects_wrong_key() {
    let sk0 = BlsScIetf::generate(&SEED_0).unwrap();
    let sk1 = BlsScIetf::generate(&SEED_1).unwrap();
    let pk0 = BlsScIetf::derive_pk(&sk0);
    let pk1 = BlsScIetf::derive_pk(&sk1);
    let proof = BlsScIetf::prove_possession(&sk0, &pk0).unwrap();

    assert!(BlsScIetf::verify_possession(&pk0, &proof).is_ok());
    assert!(BlsScIetf::verify_possession(&pk1, &proof).is_err());
  }

  #[rstest]
  fn pyecc_signature_matches() {
    let sk = BlsScIetf::sk_from_bytes(&hex!(
      "0101010101010101010101010101010101"
      "010101010101010101010101010101"
    ))
    .unwrap();
    let msg = hex!("030104010509");
    let expected = hex!(
      "96ba34fac33c7f129d602a0bc8a3d43f"
      "9abc014eceaab7359146b4b150e57b80"
      "8645738f35671e9e10e0d862a30cab70"
      "074eb5831d13e6a5b162d01eebe687d0"
      "164adbd0a864370a7c222a2768d7704d"
      "a254f1bf1823665bc2361f9dd8c00e99"
    );
    let sig = BlsScIetf::sign(&sk, &msg).unwrap();
    assert_eq!(BlsScIetf::sig_to_bytes(&sig), expected);
    assert!(BlsScIetf::verify(&sig, &msg, &BlsScIetf::derive_pk(&sk)).is_ok());
  }
}
