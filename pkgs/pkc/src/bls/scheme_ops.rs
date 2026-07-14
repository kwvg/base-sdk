//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Crate-private trait mapping each scheme marker to inner blst
//! types and operations, plus scalar field arithmetic helpers.

use super::blst_ffi::{self, Fr};
use super::error::BlsError;
use super::schemes::BlsSchemeId;
use super::BlsSigId;
use crate::prelude::*;

use blst::{blst_p1_affine, blst_p2_affine};
use dash_num::Hash256;
use rand_core::CryptoRngCore;
use zeroize::{Zeroize, Zeroizing};

use core::fmt::Debug;

/// Bit-length for scalars known to be reduced mod q (< 2^255).
pub(crate) const FR_BITS: usize = blst_ffi::FR_BITS;

/// Bit-length for unreduced 256-bit scalars (e.g. SHA256 output).
pub(crate) const SCALAR_BITS: usize = blst_ffi::SCALAR_BITS;

/// Internal trait that provides all low-level BLS operations per scheme.
pub trait BlsScheme: BlsSchemeId {
  type InnerSk: Clone + Send + Sync;
  type InnerPk: Clone + Debug + PartialEq + Eq + Send + Sync;
  type InnerSig: Clone + Debug + PartialEq + Eq + Send + Sync;

  fn generate(ikm: &[u8]) -> Result<Self::InnerSk, BlsError>;
  fn sk_from_bytes(b: &[u8; 32]) -> Result<Self::InnerSk, BlsError>;
  fn sk_to_bytes(sk: &Self::InnerSk) -> [u8; 32];
  fn derive_pk(sk: &Self::InnerSk) -> Self::InnerPk;

  fn pk_from_bytes(b: &[u8; 48]) -> Result<Self::InnerPk, BlsError>;
  fn pk_to_bytes(pk: &Self::InnerPk) -> [u8; 48];
  fn sig_from_bytes(b: &[u8; 96]) -> Result<Self::InnerSig, BlsError>;
  fn sig_to_bytes(sig: &Self::InnerSig) -> [u8; 96];

  fn sign(sk: &Self::InnerSk, msg: &[u8]) -> Result<Self::InnerSig, BlsError>;
  fn sign_with(sk: &Self::InnerSk, msg: &[u8], scheme: BlsSigId) -> Result<Self::InnerSig, BlsError>;
  fn verify(sig: &Self::InnerSig, msg: &[u8], pk: &Self::InnerPk) -> Result<(), BlsError>;
  fn verify_with(sig: &Self::InnerSig, msg: &[u8], pk: &Self::InnerPk, scheme: BlsSigId) -> Result<(), BlsError>;
  fn prove_possession(sk: &Self::InnerSk, pk: &Self::InnerPk) -> Result<Self::InnerSig, BlsError>;
  fn verify_possession(pk: &Self::InnerPk, pop: &Self::InnerSig) -> Result<(), BlsError>;
  fn dh_exchange(sk: &Self::InnerSk, pk: &Self::InnerPk) -> Result<Self::InnerPk, BlsError>;

  fn aggregate_pk(pks: &[&Self::InnerPk]) -> Result<Self::InnerPk, BlsError>;
  fn aggregate_sig(sigs: &[&Self::InnerSig]) -> Result<Self::InnerSig, BlsError>;
  fn aggregate_sk(sks: &[&Self::InnerSk]) -> Result<Self::InnerSk, BlsError> {
    if sks.is_empty() {
      return Err(BlsError::EmptyAggregation);
    }
    let byte_vecs = Zeroizing::new(sks.iter().map(|k| Self::sk_to_bytes(k)).collect::<Vec<[u8; 32]>>());
    let mut out_bytes = sum_sk_scalars(&byte_vecs).map_err(|()| BlsError::InvalidSecretKey)?;
    let result = Self::sk_from_bytes(&out_bytes).map_err(|_| BlsError::InvalidSecretKey);
    out_bytes.zeroize();
    result
  }

  fn fast_verify_aggregates(sig: &Self::InnerSig, msg: &[u8], pks: &[&Self::InnerPk]) -> Result<(), BlsError>;
  fn verify_aggregates(sig: &Self::InnerSig, msgs: &[&[u8]], pks: &[&Self::InnerPk]) -> Result<(), BlsError>;
  fn secure_verify_aggregates(sig: &Self::InnerSig, msg: &[u8], pks: &[&Self::InnerPk]) -> Result<(), BlsError>;

  fn recover_sig_shares(ids: &[&Hash256], sigs: &[&Self::InnerSig]) -> Result<Self::InnerSig, BlsError>;
  fn derive_pk_share(master_pks: &[&Self::InnerPk], id: &Hash256) -> Result<Self::InnerPk, BlsError>;

  fn zeroize_sk(sk: &mut Self::InnerSk);
}

// Scalar field arithmetic (absorbed from scalar_math.rs)

/// Convert a 32-byte participant ID to a scalar.
fn fr_from_hash(id: &Hash256) -> Fr {
  Fr::from_bendian_scalar(id.as_bytes())
}

/// Sum secret key scalars (mod group order) via blst FFI.
pub(crate) fn sum_sk_scalars(key_bytes: &[[u8; 32]]) -> Result<[u8; 32], ()> {
  let mut acc = Fr::default();
  for bytes in key_bytes {
    acc = acc + Fr::from_bendian_scalar(bytes);
  }
  let mut out_scalar = acc.to_scalar();
  let out_bytes = blst_ffi::bendian_from_scalar(&out_scalar);
  acc.zeroize();
  out_scalar.zeroize();
  Ok(out_bytes)
}

fn append_fr_scalar_bytes(out: &mut Vec<u8>, fr: Fr) {
  fr.append_scalar_le(out);
}

/// Recover a G2 point from shares via Lagrange interpolation at
/// x=0.
fn interpolate_g2(ids: &[Fr], points: &[blst_p2_affine]) -> blst_p2_affine {
  let n = ids.len();
  debug_assert_eq!(n, points.len());

  let coeffs = compute_lagrange_coeffs(ids);
  let mut scalar_bytes = zeroize::Zeroizing::new(Vec::with_capacity(n * 32));
  for &coeff in &coeffs {
    append_fr_scalar_bytes(&mut scalar_bytes, coeff);
  }

  blst_ffi::p2s_mult_pippenger(points, scalar_bytes.as_slice(), FR_BITS)
}

/// Lagrange coefficients at x=0 for the given evaluation points.
///
/// Uses Montgomery batch inversion to replace N field inversions
/// with a single inversion and 3N multiplications.
fn compute_lagrange_coeffs(ids: &[Fr]) -> Vec<Fr> {
  let n = ids.len();
  let mut nums = Vec::with_capacity(n);
  let mut dens = Vec::with_capacity(n);

  for i in 0..n {
    let mut num = fr_one();
    let mut den = fr_one();
    for j in 0..n {
      if i == j {
        continue;
      }
      num = num * ids[j];

      let diff = ids[j] - ids[i];
      den = den * diff;
    }
    nums.push(num);
    dens.push(den);
  }

  let den_invs = batch_invert_fr(&dens);

  let mut coeffs = Vec::with_capacity(n);
  for i in 0..n {
    coeffs.push(nums[i] * den_invs[i]);
  }
  coeffs
}

/// Invert a slice of Fr elements using Montgomery's trick.
///
/// Computes all inverses with a single `blst_fr_inverse` call
/// plus O(3n) multiplications.
fn batch_invert_fr(values: &[Fr]) -> Vec<Fr> {
  let n = values.len();
  if n == 0 {
    return Vec::new();
  }
  if n == 1 {
    return vec![values[0].inverse()];
  }

  // prefix[i] = values[0] * values[1] * ... * values[i]
  let mut prefix = Vec::with_capacity(n);
  prefix.push(values[0]);
  for i in 1..n {
    prefix.push(prefix[i - 1] * values[i]);
  }

  // Single inversion of the total product.
  let mut inv = prefix[n - 1].inverse();

  // Back-propagate individual inverses.
  let mut result = vec![Fr::default(); n];
  for i in (1..n).rev() {
    result[i] = inv * prefix[i - 1];
    inv = inv * values[i];
  }
  result[0] = inv;

  result
}

/// The Fr element 1.
fn fr_one() -> Fr {
  Fr::one()
}

/// Evaluate a scalar polynomial at `x`. Coefficients are in
/// ascending order: `coeffs[0] + coeffs[1]*x + ...`.
fn poly_eval(coeffs: &[Fr], x: Fr) -> Fr {
  let n = coeffs.len();
  if n == 0 {
    return Fr::default();
  }
  let mut result = coeffs[n - 1];
  for i in (0..n - 1).rev() {
    result = result * x + coeffs[i];
  }
  result
}

/// Generate secret key shares from a polynomial with the given
/// constant term.
pub(crate) fn generate_shares(
  sk_bytes: &[u8; 32],
  threshold: usize,
  ids: &[Hash256],
  rng: &mut impl CryptoRngCore,
) -> Result<Vec<(Hash256, [u8; 32])>, ()> {
  let mut coeffs = Vec::with_capacity(threshold);

  let mut sk_scalar = blst_ffi::scalar_from_bendian(sk_bytes);
  let mut sk_fr = Fr::from_scalar(&sk_scalar);
  coeffs.push(sk_fr);

  for _ in 1..threshold {
    coeffs.push(Fr::random(rng));
  }

  let mut shares = Vec::with_capacity(ids.len());
  for id in ids {
    let x = fr_from_hash(id);
    let y = poly_eval(&coeffs, x);

    let mut y_scalar = y.to_scalar();
    let y_bytes = blst_ffi::bendian_from_scalar(&y_scalar);
    y_scalar.zeroize();

    shares.push((*id, y_bytes));
  }

  // Zeroize secret polynomial coefficients.
  for coeff in &mut coeffs {
    coeff.zeroize();
  }
  sk_scalar.zeroize();
  sk_fr.zeroize();

  Ok(shares)
}

/// Compute a SHA256-weighted aggregate of G1 points.
///
/// Each public key is weighted by `SHA256(index || pk_hash)` where
/// `pk_hash = SHA256(sorted_pk_bytes)`. This prevents rogue-key
/// attacks without requiring proof-of-possession.
pub(crate) fn weighted_g1_aggregate(
  sorted_pk_bytes: &[[u8; 48]],
  deser: impl Fn(&[u8; 48]) -> Result<blst_p1_affine, BlsError>,
) -> Result<blst_p1_affine, BlsError> {
  use sha2::{Digest, Sha256};

  if sorted_pk_bytes.is_empty() {
    return Err(BlsError::EmptyAggregation);
  }

  let mut hasher = Sha256::new();
  for pk_bytes in sorted_pk_bytes {
    hasher.update(pk_bytes);
  }
  let pk_hash: [u8; 32] = hasher.finalize().into();

  let mut points = Vec::with_capacity(sorted_pk_bytes.len());
  let mut scalar_bytes = zeroize::Zeroizing::new(Vec::with_capacity(sorted_pk_bytes.len() * 32));
  for (i, pk_bytes) in sorted_pk_bytes.iter().enumerate() {
    let mut wh = Sha256::new();
    wh.update((i as u32).to_be_bytes());
    wh.update(pk_hash);
    let weight_hash: [u8; 32] = wh.finalize().into();

    let mut weight = blst_ffi::scalar_from_bendian(&weight_hash);
    scalar_bytes.extend_from_slice(&weight.b);
    weight.zeroize();

    points.push(deser(pk_bytes)?);
  }

  Ok(blst_ffi::p1s_mult_pippenger(
    &points,
    scalar_bytes.as_slice(),
    SCALAR_BITS,
  ))
}

/// Recover a G2 signature from threshold shares given as affine
/// points. Validates input length and rejects duplicate IDs.
pub(crate) fn recover_sig_shares_affine(ids: &[&Hash256], sigs: &[blst_p2_affine]) -> Result<blst_p2_affine, BlsError> {
  if ids.len() != sigs.len() {
    return Err(BlsError::CountMismatch);
  }
  if sigs.len() < 2 {
    return Err(BlsError::InsufficientShares);
  }

  // Reject duplicate share IDs.
  let mut sorted_ids: Vec<&Hash256> = ids.to_vec();
  sorted_ids.sort();
  for pair in sorted_ids.windows(2) {
    if pair[0] == pair[1] {
      return Err(BlsError::DuplicateShareId);
    }
  }

  let fr_ids: Vec<Fr> = ids.iter().map(|id| fr_from_hash(id)).collect();
  Ok(interpolate_g2(&fr_ids, sigs))
}

/// Derive a public key share by evaluating a G1 polynomial at the
/// given participant ID.
pub(crate) fn derive_pk_share_affine(pks: &[blst_p1_affine], id: &Hash256) -> Result<blst_p1_affine, BlsError> {
  if pks.is_empty() {
    return Err(BlsError::EmptyAggregation);
  }

  let x = fr_from_hash(id);
  let mut x_power = fr_one();
  let mut scalar_bytes = zeroize::Zeroizing::new(Vec::with_capacity(pks.len() * 32));
  for _ in pks {
    append_fr_scalar_bytes(&mut scalar_bytes, x_power);

    x_power = x_power * x;
  }

  Ok(blst_ffi::p1s_mult_pippenger(pks, scalar_bytes.as_slice(), FR_BITS))
}
