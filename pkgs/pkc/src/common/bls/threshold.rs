//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Lagrange interpolation and polynomial evaluation over the BLS12-381 scalar
//! field, used by threshold BLS in both bls_ietf and bls_chia.

use crate::bls::blst_ffi;
use crate::prelude::*;

use blst::{blst_fr, blst_p1, blst_p2};
use dash_num::Hash256;

/// Evaluate a polynomial at `x`. Coefficients are in ascending order:
/// `coeffs[0] + coeffs[1]*x + ...`.
pub(crate) fn poly_eval(coeffs: &[blst_fr], x: &blst_fr) -> blst_fr {
  // Horner's method: result = c[n-1], then for each
  // i from n-2..=0: result = result*x + c[i].
  let n = coeffs.len();
  if n == 0 {
    return blst_fr::default();
  }
  let mut result = coeffs[n - 1];
  for i in (0..n - 1).rev() {
    let tmp = blst_ffi::fr_mul(&result, x);
    result = blst_ffi::fr_add(&tmp, &coeffs[i]);
  }
  result
}

/// Recover a G2 point from shares via Lagrange interpolation at x=0.
///
/// `ids` and `points` must have the same length >= 1.
/// Each id must be non-zero and unique.
pub(crate) fn interpolate_g2(ids: &[blst_fr], points: &[blst_p2]) -> blst_p2 {
  let n = ids.len();

  // Compute Lagrange coefficients at x=0:
  //   L_i = prod_{j!=i} id_j / (id_j - id_i)
  let coeffs = compute_lagrange_coeffs(ids);

  let mut result = blst_p2::default();
  for i in 0..n {
    // Convert Fr coefficient to scalar for point
    // multiplication.
    let scalar = blst_ffi::scalar_from_fr(&coeffs[i]);
    let term = blst_ffi::p2_mult(&points[i], &scalar.b, 255);
    result = blst_ffi::p2_add_or_double(&result, &term);
  }
  result
}

/// Lagrange coefficients at x=0 for the given evaluation points (ids).
fn compute_lagrange_coeffs(ids: &[blst_fr]) -> Vec<blst_fr> {
  let n = ids.len();
  let mut coeffs = Vec::with_capacity(n);

  for i in 0..n {
    // L_i = prod_{j!=i} ids[j] / (ids[j] - ids[i])
    let mut num = fr_one();
    let mut den = fr_one();

    for j in 0..n {
      if i == j {
        continue;
      }
      // num *= ids[j]
      num = blst_ffi::fr_mul(&num, &ids[j]);

      // den *= (ids[j] - ids[i])
      let diff = blst_ffi::fr_sub(&ids[j], &ids[i]);
      den = blst_ffi::fr_mul(&den, &diff);
    }

    let den_inv = blst_ffi::fr_inverse(&den);
    let coeff = blst_ffi::fr_mul(&num, &den_inv);
    coeffs.push(coeff);
  }
  coeffs
}

/// The Fr element 1.
fn fr_one() -> blst_fr {
  let one = [1u64, 0, 0, 0];
  blst_ffi::fr_from_uint64(&one)
}

/// Evaluate a polynomial of G1 points at scalar `x`.
///
/// `coeffs_g1[0] + coeffs_g1[1]*x + coeffs_g1[2]*x^2 + ...`
/// Uses Horner's method.
pub(crate) fn eval_poly_g1(coeffs_g1: &[blst_p1], x: &blst_fr) -> blst_p1 {
  let n = coeffs_g1.len();
  if n == 0 {
    return blst_p1::default();
  }
  let x_scalar = blst_ffi::scalar_from_fr(x);
  let mut result = coeffs_g1[n - 1];
  for i in (0..n - 1).rev() {
    let tmp = blst_ffi::p1_mult(&blst_ffi::p1_to_affine(&result), &x_scalar.b, 255);
    let tmp = blst_ffi::p1_from_affine(&tmp);
    result = blst_ffi::p1_add_or_double(&tmp, &coeffs_g1[i]);
  }
  result
}

/// Convert a 32-byte participant ID to a scalar.
pub(crate) fn fr_from_hash(id: &Hash256) -> blst_fr {
  let scalar = blst_ffi::scalar_from_bendian(id.as_bytes());
  blst_ffi::fr_from_scalar(&scalar)
}
