//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Lagrange interpolation and polynomial evaluation over the BLS12-381 scalar
//! field, used by threshold BLS in both bls_ietf and bls_chia.

use crate::prelude::*;

use blst::*;
use dash_num::Hash256;

/// Evaluate a polynomial at `x`. Coefficients are in ascending order:
/// `coeffs[0] + coeffs[1]*x + ...`.
#[expect(unsafe_code, reason = "blst C FFI")]
pub(crate) fn poly_eval(coeffs: &[blst_fr], x: &blst_fr) -> blst_fr {
  // Horner's method: result = c[n-1], then for each
  // i from n-2..=0: result = result*x + c[i].
  let n = coeffs.len();
  if n == 0 {
    return blst_fr::default();
  }
  let mut result = coeffs[n - 1];
  for i in (0..n - 1).rev() {
    let mut tmp = blst_fr::default();
    unsafe { blst_fr_mul(&mut tmp, &result, x) };
    unsafe { blst_fr_add(&mut result, &tmp, &coeffs[i]) };
  }
  result
}

/// Recover a G2 point from shares via Lagrange interpolation at x=0.
///
/// `ids` and `points` must have the same length >= 1.
/// Each id must be non-zero and unique.
#[expect(unsafe_code, reason = "blst C FFI")]
pub(crate) fn interpolate_g2(ids: &[blst_fr], points: &[blst_p2]) -> blst_p2 {
  let n = ids.len();

  // Compute Lagrange coefficients at x=0:
  //   λ_i = ∏_{j≠i} id_j / (id_j - id_i)
  let coeffs = compute_lagrange_coeffs(ids);

  let mut result = blst_p2::default();
  for i in 0..n {
    // Convert Fr coefficient to scalar for point
    // multiplication.
    let mut scalar = blst_scalar::default();
    unsafe { blst_scalar_from_fr(&mut scalar, &coeffs[i]) };

    let mut term = blst_p2::default();
    unsafe { blst_p2_mult(&mut term, &points[i], scalar.b.as_ptr(), 255) };
    unsafe { blst_p2_add_or_double(&mut result, &result, &term) };
  }
  result
}

/// Lagrange coefficients at x=0 for the given evaluation points (ids).
#[expect(unsafe_code, reason = "blst C FFI")]
fn compute_lagrange_coeffs(ids: &[blst_fr]) -> Vec<blst_fr> {
  let n = ids.len();
  let mut coeffs = Vec::with_capacity(n);

  for i in 0..n {
    // λ_i = ∏_{j≠i} ids[j] / (ids[j] - ids[i])
    let mut num = fr_one();
    let mut den = fr_one();

    for j in 0..n {
      if i == j {
        continue;
      }
      // num *= ids[j]
      let mut tmp = blst_fr::default();
      unsafe { blst_fr_mul(&mut tmp, &num, &ids[j]) };
      num = tmp;

      // den *= (ids[j] - ids[i])
      let mut diff = blst_fr::default();
      unsafe { blst_fr_sub(&mut diff, &ids[j], &ids[i]) };
      let mut tmp2 = blst_fr::default();
      unsafe { blst_fr_mul(&mut tmp2, &den, &diff) };
      den = tmp2;
    }

    let mut den_inv = blst_fr::default();
    unsafe { blst_fr_inverse(&mut den_inv, &den) };

    let mut coeff = blst_fr::default();
    unsafe { blst_fr_mul(&mut coeff, &num, &den_inv) };
    coeffs.push(coeff);
  }
  coeffs
}

/// The Fr element 1.
#[expect(unsafe_code, reason = "blst C FFI")]
fn fr_one() -> blst_fr {
  let mut fr = blst_fr::default();
  let one = [1u64, 0, 0, 0];
  unsafe { blst_fr_from_uint64(&mut fr, one.as_ptr()) };
  fr
}

/// Evaluate a polynomial of G1 points at scalar `x`.
///
/// `coeffs_g1[0] + coeffs_g1[1]*x + coeffs_g1[2]*x^2 + ...`
/// Uses Horner's method.
#[expect(unsafe_code, reason = "blst C FFI")]
pub(crate) fn eval_poly_g1(coeffs_g1: &[blst_p1], x: &blst_fr) -> blst_p1 {
  let n = coeffs_g1.len();
  if n == 0 {
    return blst_p1::default();
  }
  let mut x_scalar = blst_scalar::default();
  unsafe { blst_scalar_from_fr(&mut x_scalar, x) };
  let mut result = coeffs_g1[n - 1];
  for i in (0..n - 1).rev() {
    let mut tmp = blst_p1::default();
    unsafe { blst_p1_mult(&mut tmp, &result, x_scalar.b.as_ptr(), 255) };
    unsafe { blst_p1_add_or_double(&mut result, &tmp, &coeffs_g1[i]) };
  }
  result
}

/// Convert a 32-byte participant ID to a scalar.
#[expect(unsafe_code, reason = "blst C FFI")]
pub(crate) fn fr_from_hash(id: &Hash256) -> blst_fr {
  let mut scalar = blst_scalar::default();
  unsafe { blst_scalar_from_bendian(&mut scalar, id.as_bytes().as_ptr()) };
  let mut fr = blst_fr::default();
  unsafe { blst_fr_from_scalar(&mut fr, &scalar) };
  fr
}
