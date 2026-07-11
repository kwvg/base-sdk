//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Thresholds for legacy scheme (m-of-n secret sharing and signature recovery).

use super::pk::PublicKey;
use super::sig::Signature;
use super::sk::SecretKey;
use crate::bls::blst_ffi::{self, Fr};
use crate::bls::BlsError;
use crate::common::bls::threshold as math;
use crate::prelude::*;

use blst::{blst_p1, blst_p2};
use dash_num::Hash256;
use rand_core::CryptoRngCore;

use core::fmt;

/// Secret key share for threshold signing.
#[derive(Clone)]
pub struct SecretKeyShare {
  id: Hash256,
  sk: SecretKey,
}

impl SecretKeyShare {
  /// Construct a secret key share from an ID and a secret key.
  pub fn new(id: Hash256, sk: SecretKey) -> Self {
    Self { id, sk }
  }

  /// Participant identifier (32-byte hash).
  pub fn id(&self) -> &Hash256 {
    &self.id
  }

  /// Sign a 32-byte message, producing a signature share.
  pub fn sign(&self, msg: &[u8; 32]) -> SignatureShare {
    SignatureShare {
      id: self.id,
      sig: self.sk.sign(msg),
    }
  }

  /// The underlying secret key.
  pub fn secret_key(&self) -> &SecretKey {
    &self.sk
  }
}

impl fmt::Debug for SecretKeyShare {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "SecretKeyShare(id={:?})", self.id)
  }
}

/// Signature share from one threshold participant.
#[derive(Clone)]
pub struct SignatureShare {
  id: Hash256,
  sig: Signature,
}

impl SignatureShare {
  /// Construct a signature share from an ID and a signature.
  pub fn new(id: Hash256, sig: Signature) -> Self {
    Self { id, sig }
  }

  /// Participant identifier (32-byte hash).
  pub fn id(&self) -> &Hash256 {
    &self.id
  }

  /// The underlying signature.
  pub fn signature(&self) -> &Signature {
    &self.sig
  }
}

impl fmt::Debug for SignatureShare {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "SignatureShare(id={:?})", self.id)
  }
}

/// Split a secret key into shares for the given participant
/// IDs, requiring `threshold` shares to recover.
///
/// # Errors
///
/// Returns `ThresholdTooLarge` if `threshold > ids.len()` or
/// either is zero.
pub fn split_sk(
  sk: &SecretKey,
  threshold: usize,
  ids: &[Hash256],
  rng: &mut impl CryptoRngCore,
) -> Result<Vec<SecretKeyShare>, BlsError> {
  if threshold == 0 || ids.is_empty() || threshold > ids.len() {
    return Err(BlsError::ThresholdTooLarge);
  }

  // Reject zero IDs.
  for id in ids {
    if id.is_null() {
      return Err(BlsError::ThresholdTooLarge);
    }
  }

  // Reject duplicate IDs.
  for i in 0..ids.len() {
    for j in (i + 1)..ids.len() {
      if ids[i] == ids[j] {
        return Err(BlsError::DuplicateShareId);
      }
    }
  }

  let raw = crate::common::bls::generate_shares(&sk.to_bytes(), threshold, ids, rng)
    .map_err(|()| BlsError::InvalidSecretKey)?;

  raw
    .into_iter()
    .map(|(id, bytes)| {
      let share_sk = SecretKey::from_bytes(&bytes).map_err(|_| BlsError::InvalidSecretKey)?;
      Ok(SecretKeyShare { id, sk: share_sk })
    })
    .collect()
}

/// Recover a full signature from threshold signature shares via Lagrange
/// interpolation in G2.
///
/// # Errors
///
/// Returns `InsufficientShares` if fewer than 2 shares.
pub fn recover_sig(shares: &[&SignatureShare]) -> Result<Signature, BlsError> {
  if shares.len() < 2 {
    return Err(BlsError::InsufficientShares);
  }

  // Check for duplicate IDs
  for i in 0..shares.len() {
    for j in (i + 1)..shares.len() {
      if shares[i].id == shares[j].id {
        return Err(BlsError::DuplicateShareId);
      }
    }
  }

  let ids: Vec<Fr> = shares.iter().map(|s| math::fr_from_hash(&s.id)).collect();
  let points: Vec<blst_p2> = shares.iter().map(|s| blst_ffi::p2_from_affine(&s.sig.0)).collect();

  let recovered = math::interpolate_g2(&ids, &points);
  Ok(Signature::from_inner(blst_ffi::p2_to_affine(&recovered)))
}

/// Derive a public key share by evaluating the master public
/// key polynomial at the given participant id.
pub fn derive_pk_share(master_pks: &[&PublicKey], id: &Hash256) -> Result<PublicKey, BlsError> {
  if master_pks.is_empty() {
    return Err(BlsError::EmptyAggregation);
  }
  let coeffs_g1: Vec<blst_p1> = master_pks.iter().map(|pk| blst_ffi::p1_from_affine(&pk.0)).collect();

  let x = math::fr_from_hash(id);
  let result = math::eval_poly_g1(&coeffs_g1, &x);

  Ok(PublicKey::from_inner(blst_ffi::p1_to_affine(&result)))
}
