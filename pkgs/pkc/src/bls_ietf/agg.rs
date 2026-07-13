//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Aggregation and batch verification for IETF BLS.

use super::error::Error;
use super::pk::PublicKey;
use super::sig::Signature;
use super::sk::SecretKey;
use super::DST;
use crate::bls::blst_ffi;
use crate::prelude::*;

use blst::min_pk;
use blst::{blst_p1, BLST_ERROR};
use sha2::{Digest, Sha256};

/// Aggregate multiple public keys into one.
pub fn aggregate_pk(keys: &[&PublicKey]) -> Result<PublicKey, Error> {
  if keys.is_empty() {
    return Err(Error::EmptyAggregation);
  }
  // Not repr(transparent), so collect inner refs.
  let inner_refs: &[&min_pk::PublicKey] = &keys.iter().map(|k| &k.0).collect::<Vec<_>>();
  let agg = min_pk::AggregatePublicKey::aggregate(inner_refs, true).map_err(|_| Error::InvalidPublicKey)?;
  Ok(PublicKey::from_inner(agg.to_public_key()))
}

/// Aggregate multiple signatures into one.
pub fn aggregate_sig(sigs: &[&Signature]) -> Result<Signature, Error> {
  if sigs.is_empty() {
    return Err(Error::EmptyAggregation);
  }
  let inner_refs: Vec<&min_pk::Signature> = sigs.iter().map(|s| &s.0).collect();
  let agg = min_pk::AggregateSignature::aggregate(&inner_refs, true).map_err(|_| Error::InvalidSignature)?;
  Ok(Signature::from_inner(agg.to_signature()))
}

/// Verify an aggregated signature where every signer signed the same message.
pub fn fast_verify_aggregates(sig: &Signature, msg: &[u8], pks: &[&PublicKey]) -> Result<(), Error> {
  if pks.is_empty() {
    return Err(Error::EmptyAggregation);
  }
  let inner_pks: Vec<&min_pk::PublicKey> = pks.iter().map(|k| &k.0).collect();
  let result = sig.0.fast_aggregate_verify(true, msg, DST, &inner_pks);
  if result == BLST_ERROR::BLST_SUCCESS {
    Ok(())
  } else {
    Err(Error::VerifyFailed)
  }
}

/// Verify an aggregated signature where each signer signed a distinct message.
pub fn verify_aggregates(sig: &Signature, msgs: &[&[u8]], pks: &[&PublicKey]) -> Result<(), Error> {
  if pks.len() != msgs.len() {
    return Err(Error::CountMismatch);
  }
  if pks.is_empty() {
    return Err(Error::EmptyAggregation);
  }
  let inner_pks: Vec<&min_pk::PublicKey> = pks.iter().map(|k| &k.0).collect();
  let result = sig.0.aggregate_verify(true, msgs, DST, &inner_pks, true);
  if result == BLST_ERROR::BLST_SUCCESS {
    Ok(())
  } else {
    Err(Error::VerifyFailed)
  }
}

/// Securely aggregate and verify signatures with public-key weighting.
///
/// Algorithm:
/// 1. Sort public keys by serialized (compressed) bytes
/// 2. Compute `pk_hash = SHA256(pk1 || pk2 || ... || pkN)` (sorted order)
/// 3. For each sorted pk at index i: `weight_i = SHA256(i_as_4_bytes ||
///    pk_hash) mod order`
/// 4. Compute weighted public key: `agg_pk = sum(weight_i * pk_i)`
/// 5. Verify the aggregate signature against `agg_pk` and the message
pub fn secure_verify_aggregates(sig: &Signature, msg: &[u8], pks: &[&PublicKey]) -> Result<(), Error> {
  if pks.is_empty() {
    return Err(Error::EmptyAggregation);
  }

  let mut sorted: Vec<[u8; 48]> = pks.iter().map(|pk| pk.to_bytes()).collect();
  sorted.sort();

  let mut hasher = Sha256::new();
  for pk_bytes in &sorted {
    hasher.update(pk_bytes);
  }
  let pk_hash: [u8; 32] = hasher.finalize().into();

  let mut acc = blst_p1::default();

  for (i, pk_bytes) in sorted.iter().enumerate() {
    // weight = SHA256(i_as_4_bytes_be || pk_hash) mod order
    let mut weight_hasher = Sha256::new();
    let idx_bytes = (i as u32).to_be_bytes();
    weight_hasher.update(idx_bytes);
    weight_hasher.update(pk_hash);
    let weight_hash: [u8; 32] = weight_hasher.finalize().into();

    // blst_p1_mult reduces internally.
    let weight = blst_ffi::scalar_from_bendian(&weight_hash);

    let pk_aff = blst_ffi::p1_uncompress(pk_bytes).map_err(|_| Error::InvalidPublicKey)?;
    let weighted = blst_ffi::p1_mult(&pk_aff, &weight.b, 256);
    let weighted = blst_ffi::p1_from_affine(&weighted);
    acc = blst_ffi::p1_add_or_double(&acc, &weighted);
  }

  let agg_pk_aff = blst_ffi::p1_to_affine(&acc);
  let agg_pk_bytes = blst_ffi::p1_affine_compress(&agg_pk_aff);
  let agg_pk = PublicKey::from_bytes(&agg_pk_bytes).map_err(|_| Error::InvalidPublicKey)?;

  sig.verify(msg, &agg_pk)
}

/// Sum multiple secret keys (mod group order).
pub fn aggregate_sk(keys: &[&SecretKey]) -> Result<SecretKey, Error> {
  use zeroize::Zeroize;
  if keys.is_empty() {
    return Err(Error::EmptyAggregation);
  }
  let byte_vecs = zeroize::Zeroizing::new(keys.iter().map(|k| k.to_bytes()).collect::<Vec<[u8; 32]>>());
  let mut out_bytes = crate::common::bls::sum_sk_scalars(&byte_vecs).map_err(|()| Error::InvalidSecretKey)?;
  let result = SecretKey::from_bytes(&out_bytes).map_err(|_| Error::InvalidSecretKey);
  out_bytes.zeroize();
  result
}
