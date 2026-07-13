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

use blst::{blst_p1_affine, blst_p2_affine, min_pk, BLST_ERROR};
use dash_num::Hash256;
use zeroize::Zeroize;

// IETF domain separation tags.
pub(crate) const DST_BASIC: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";
pub(crate) const DST_POP: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";
pub(crate) const DST_POP_PROVE: &[u8] = b"BLS_POP_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";

impl BlsScheme for BlsScIetf {
  type InnerSk = min_pk::SecretKey;
  type InnerPk = min_pk::PublicKey;
  type InnerSig = min_pk::Signature;

  fn generate(ikm: &[u8]) -> Result<Self::InnerSk, BlsError> {
    min_pk::SecretKey::key_gen(ikm, &[]).map_err(|_| BlsError::InvalidKeyMaterial)
  }

  fn sk_from_bytes(b: &[u8; 32]) -> Result<Self::InnerSk, BlsError> {
    min_pk::SecretKey::from_bytes(b).map_err(|_| BlsError::InvalidSecretKey)
  }

  fn sk_to_bytes(sk: &Self::InnerSk) -> [u8; 32] {
    sk.to_bytes()
  }

  fn derive_pk(sk: &Self::InnerSk) -> Self::InnerPk {
    sk.sk_to_pk()
  }

  fn pk_from_bytes(b: &[u8; 48]) -> Result<Self::InnerPk, BlsError> {
    min_pk::PublicKey::from_bytes(b).map_err(|_| BlsError::InvalidPublicKey)
  }

  fn pk_to_bytes(pk: &Self::InnerPk) -> [u8; 48] {
    pk.compress()
  }

  fn sig_from_bytes(b: &[u8; 96]) -> Result<Self::InnerSig, BlsError> {
    min_pk::Signature::from_bytes(b).map_err(|_| BlsError::InvalidSignature)
  }

  fn sig_to_bytes(sig: &Self::InnerSig) -> [u8; 96] {
    sig.compress()
  }

  fn sign(sk: &Self::InnerSk, msg: &[u8]) -> Self::InnerSig {
    sk.sign(msg, DST_BASIC, &[])
  }

  fn sign_with(sk: &Self::InnerSk, msg: &[u8], scheme: super::BlsSigId) -> Result<Self::InnerSig, BlsError> {
    let dst = match scheme {
      super::BlsSigId::Basic => DST_BASIC,
      super::BlsSigId::ProofOfPossession => DST_POP,
    };
    Ok(sk.sign(msg, dst, &[]))
  }

  fn verify(sig: &Self::InnerSig, msg: &[u8], pk: &Self::InnerPk) -> Result<(), BlsError> {
    let result = sig.verify(true, msg, DST_BASIC, &[], pk, true);
    if result == BLST_ERROR::BLST_SUCCESS {
      Ok(())
    } else {
      Err(BlsError::VerifyFailed)
    }
  }

  fn verify_with(
    sig: &Self::InnerSig,
    msg: &[u8],
    pk: &Self::InnerPk,
    scheme: super::BlsSigId,
  ) -> Result<(), BlsError> {
    let dst = match scheme {
      super::BlsSigId::Basic => DST_BASIC,
      super::BlsSigId::ProofOfPossession => DST_POP,
    };
    let result = sig.verify(true, msg, dst, &[], pk, true);
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
    let result = pop.verify(true, &pk_bytes, DST_POP_PROVE, &[], pk, true);
    if result == BLST_ERROR::BLST_SUCCESS {
      Ok(())
    } else {
      Err(BlsError::VerifyFailed)
    }
  }

  fn dh_exchange(sk: &Self::InnerSk, peer_pk: &Self::InnerPk) -> Result<Self::InnerPk, BlsError> {
    let compressed = peer_pk.compress();
    let aff = blst_ffi::p1_uncompress(&compressed).map_err(|_| BlsError::InvalidPublicKey)?;
    let mut sk_bytes = sk.to_bytes();
    let mut sk_scalar = blst_ffi::scalar_from_bendian(&sk_bytes);
    let out_aff = blst_ffi::p1_mult(&aff, &sk_scalar.b, blst_ffi::FR_BITS);
    let out_bytes = blst_ffi::p1_affine_compress(&out_aff);
    sk_bytes.zeroize();
    sk_scalar.zeroize();
    Self::pk_from_bytes(&out_bytes)
  }

  fn aggregate_pk(pks: &[&Self::InnerPk]) -> Result<Self::InnerPk, BlsError> {
    if pks.is_empty() {
      return Err(BlsError::EmptyAggregation);
    }
    let agg = min_pk::AggregatePublicKey::aggregate(pks, true).map_err(|_| BlsError::InvalidPublicKey)?;
    Ok(agg.to_public_key())
  }

  fn aggregate_sig(sigs: &[&Self::InnerSig]) -> Result<Self::InnerSig, BlsError> {
    if sigs.is_empty() {
      return Err(BlsError::EmptyAggregation);
    }
    let agg = min_pk::AggregateSignature::aggregate(sigs, true).map_err(|_| BlsError::InvalidSignature)?;
    Ok(agg.to_signature())
  }

  fn fast_verify_aggregates(sig: &Self::InnerSig, msg: &[u8], pks: &[&Self::InnerPk]) -> Result<(), BlsError> {
    if pks.is_empty() {
      return Err(BlsError::EmptyAggregation);
    }
    let result = sig.fast_aggregate_verify(true, msg, DST_BASIC, pks);
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
    let result = sig.aggregate_verify(true, msgs, DST_BASIC, pks, true);
    if result == BLST_ERROR::BLST_SUCCESS {
      Ok(())
    } else {
      Err(BlsError::VerifyFailed)
    }
  }

  fn secure_verify_aggregates(sig: &Self::InnerSig, msg: &[u8], pks: &[&Self::InnerPk]) -> Result<(), BlsError> {
    use crate::prelude::Vec;

    if pks.is_empty() {
      return Err(BlsError::EmptyAggregation);
    }

    let mut sorted: Vec<[u8; 48]> = pks.iter().map(|pk| pk.compress()).collect();
    sorted.sort();

    let deser = |b: &[u8; 48]| blst_ffi::p1_uncompress(b).map_err(|_| BlsError::InvalidPublicKey);

    let agg_pk_aff = scheme_ops::weighted_g1_aggregate(&sorted, deser)?;
    let agg_pk_bytes = blst_ffi::p1_affine_compress(&agg_pk_aff);
    let agg_pk = Self::pk_from_bytes(&agg_pk_bytes).map_err(|_| BlsError::InvalidPublicKey)?;
    Self::verify(sig, msg, &agg_pk)
  }

  fn recover_sig_shares(ids: &[&Hash256], sigs: &[&Self::InnerSig]) -> Result<Self::InnerSig, BlsError> {
    let aff_sigs: crate::prelude::Vec<blst_p2_affine> = sigs
      .iter()
      .map(|s| blst_ffi::p2_uncompress(&s.compress()).map_err(|_| BlsError::InvalidSignature))
      .collect::<Result<_, _>>()?;

    let recovered = scheme_ops::recover_sig_shares_affine(ids, &aff_sigs)?;
    let bytes = blst_ffi::p2_affine_compress(&recovered);
    Self::sig_from_bytes(&bytes).map_err(|_| BlsError::InvalidSignature)
  }

  fn derive_pk_share(master_pks: &[&Self::InnerPk], id: &Hash256) -> Result<Self::InnerPk, BlsError> {
    if master_pks.is_empty() {
      return Err(BlsError::EmptyAggregation);
    }
    let aff_pks: crate::prelude::Vec<blst_p1_affine> = master_pks
      .iter()
      .map(|pk| blst_ffi::p1_uncompress(&pk.compress()).map_err(|_| BlsError::InvalidPublicKey))
      .collect::<Result<_, _>>()?;

    let result = scheme_ops::derive_pk_share_affine(&aff_pks, id)?;
    let bytes = blst_ffi::p1_affine_compress(&result);
    Self::pk_from_bytes(&bytes)
  }

  fn zeroize_sk(_sk: &mut Self::InnerSk) {
    // blst::min_pk::SecretKey handles zeroization internally.
  }
}
