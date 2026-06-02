//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Aggregation and secure verification for legacy BLS.

use blst::*;
use sha2::{Digest, Sha256};

use super::error::Error;
use super::pk::PublicKey;
use super::sig::Signature;
use super::sk::SecretKey;
use crate::prelude::*;

/// Aggregate multiple legacy BLS public keys (simple point addition in G1).
#[expect(unsafe_code, reason = "blst C FFI")]
pub fn aggregate_pk(keys: &[&PublicKey]) -> Result<PublicKey, Error> {
  if keys.is_empty() {
    return Err(Error::EmptyAggregation);
  }
  let mut acc = blst_p1::default();
  unsafe { blst_p1_from_affine(&mut acc, &keys[0].0) };
  for k in &keys[1..] {
    let mut tmp = blst_p1::default();
    unsafe { blst_p1_from_affine(&mut tmp, &k.0) };
    unsafe { blst_p1_add_or_double(&mut acc, &acc, &tmp) };
  }
  let mut aff = blst_p1_affine::default();
  unsafe { blst_p1_to_affine(&mut aff, &acc) };
  Ok(PublicKey::from_inner(aff))
}

/// Aggregate multiple legacy BLS signatures (simple point addition in G2).
#[expect(unsafe_code, reason = "blst C FFI")]
pub fn aggregate_sig(sigs: &[&Signature]) -> Result<Signature, Error> {
  if sigs.is_empty() {
    return Err(Error::EmptyAggregation);
  }
  let mut acc = blst_p2::default();
  unsafe { blst_p2_from_affine(&mut acc, &sigs[0].0) };
  for s in &sigs[1..] {
    let mut tmp = blst_p2::default();
    unsafe { blst_p2_from_affine(&mut tmp, &s.0) };
    unsafe { blst_p2_add_or_double(&mut acc, &acc, &tmp) };
  }
  let mut aff = blst_p2_affine::default();
  unsafe { blst_p2_to_affine(&mut aff, &acc) };
  Ok(Signature::from_inner(aff))
}

/// Verify an aggregated legacy BLS signature over one message and multiple
/// public keys.
pub fn verify_aggregates(sig: &Signature, msg: &[u8; 32], pks: &[&PublicKey]) -> Result<(), Error> {
  if pks.is_empty() {
    return Err(Error::EmptyAggregation);
  }
  let agg_pk = aggregate_pk(pks)?;
  sig.verify(msg, &agg_pk)
}

/// Verify an aggregated legacy BLS signature where every signer signed the
/// same message. Equivalent to `verify_aggregates` for the legacy scheme.
pub fn fast_verify_aggregates(sig: &Signature, msg: &[u8; 32], pks: &[&PublicKey]) -> Result<(), Error> {
  verify_aggregates(sig, msg, pks)
}

/// Securely aggregate and verify signatures with public-key weighting.
///
/// Algorithm:
/// 1. Sort public keys by serialized (legacy) bytes
/// 2. Compute `pk_hash = SHA256(pk1 || pk2 || ... || pkN)` (sorted order)
/// 3. For each sorted pk at index i: `weight_i = SHA256(i_as_4_bytes ||
///    pk_hash) mod order`
/// 4. Compute weighted public key: `agg_pk = sum(weight_i * pk_i)`
/// 5. Verify the aggregate signature against `agg_pk` and the message
#[expect(unsafe_code, reason = "blst C FFI")]
pub fn secure_verify_aggregates(sig: &Signature, msg: &[u8; 32], pks: &[&PublicKey]) -> Result<(), Error> {
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

    let mut weight = blst_scalar::default();
    // blst_p1_mult reduces internally.
    unsafe { blst_scalar_from_bendian(&mut weight, weight_hash.as_ptr()) };

    let pk = PublicKey::from_bytes(pk_bytes).map_err(|_| Error::InvalidPublicKey)?;
    let mut pk_proj = blst_p1::default();
    unsafe { blst_p1_from_affine(&mut pk_proj, &pk.0) };

    let mut weighted = blst_p1::default();
    unsafe { blst_p1_mult(&mut weighted, &pk_proj, weight.b.as_ptr(), 256) };

    unsafe { blst_p1_add_or_double(&mut acc, &acc, &weighted) };
  }

  let mut agg_pk_aff = blst_p1_affine::default();
  unsafe { blst_p1_to_affine(&mut agg_pk_aff, &acc) };
  let agg_pk = PublicKey::from_inner(agg_pk_aff);

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
