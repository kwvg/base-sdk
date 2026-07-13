//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Bridging routines for unsafe blst FFI operations.

use blst::*;

/// Bit-length for scalars known to be reduced mod q (< 2^255).
pub(crate) const FR_BITS: usize = 255;

extern "C" {
  fn blst_p2_generator() -> *const blst_p2;
  fn blst_p1_affine_generator() -> *const blst_p1_affine;
  fn blst_sk_check(sk: *const blst_scalar) -> bool;
}

fn p1_affine_generator() -> blst_p1_affine {
  unsafe { *blst_p1_affine_generator() }
}

pub(crate) fn bendian_from_fp(value: &blst_fp) -> [u8; 48] {
  let mut out = [0u8; 48];
  unsafe { blst_bendian_from_fp(out.as_mut_ptr(), value) };
  out
}

pub(crate) fn bendian_from_scalar(scalar: &blst_scalar) -> [u8; 32] {
  let mut out = [0u8; 32];
  unsafe { blst_bendian_from_scalar(out.as_mut_ptr(), scalar) };
  out
}

pub(crate) fn fp2_add(a: &blst_fp2, b: &blst_fp2) -> blst_fp2 {
  let mut out = blst_fp2::default();
  unsafe { blst_fp2_add(&mut out, a, b) };
  out
}

pub(crate) fn fp2_cneg(value: &blst_fp2, flag: bool) -> blst_fp2 {
  let mut out = *value;
  unsafe { blst_fp2_cneg(&mut out, value, flag) };
  out
}

pub(crate) fn fp2_inverse(value: &blst_fp2) -> blst_fp2 {
  let mut out = blst_fp2::default();
  unsafe { blst_fp2_inverse(&mut out, value) };
  out
}

pub(crate) fn fp2_mul(a: &blst_fp2, b: &blst_fp2) -> blst_fp2 {
  let mut out = blst_fp2::default();
  unsafe { blst_fp2_mul(&mut out, a, b) };
  out
}

pub(crate) fn fp2_sqr(value: &blst_fp2) -> blst_fp2 {
  let mut out = blst_fp2::default();
  unsafe { blst_fp2_sqr(&mut out, value) };
  out
}

pub(crate) fn fp2_sqrt(value: &blst_fp2) -> Option<blst_fp2> {
  let mut out = blst_fp2::default();
  unsafe { blst_fp2_sqrt(&mut out, value) }.then_some(out)
}

pub(crate) fn fp_add(a: &blst_fp, b: &blst_fp) -> blst_fp {
  let mut out = blst_fp::default();
  unsafe { blst_fp_add(&mut out, a, b) };
  out
}

pub(crate) fn fp_cneg(value: &blst_fp, flag: bool) -> blst_fp {
  let mut out = *value;
  unsafe { blst_fp_cneg(&mut out, value, flag) };
  out
}

pub(crate) fn fp_from_bendian(bytes: &[u8; 48]) -> blst_fp {
  let mut out = blst_fp::default();
  unsafe { blst_fp_from_bendian(&mut out, bytes.as_ptr()) };
  out
}

pub(crate) fn fp_mul(a: &blst_fp, b: &blst_fp) -> blst_fp {
  let mut out = blst_fp::default();
  unsafe { blst_fp_mul(&mut out, a, b) };
  out
}

pub(crate) fn fp_sub(a: &blst_fp, b: &blst_fp) -> blst_fp {
  let mut out = blst_fp::default();
  unsafe { blst_fp_sub(&mut out, a, b) };
  out
}

pub(crate) fn fr_add(a: &blst_fr, b: &blst_fr) -> blst_fr {
  let mut out = blst_fr::default();
  unsafe { blst_fr_add(&mut out, a, b) };
  out
}

pub(crate) fn fr_from_scalar(scalar: &blst_scalar) -> blst_fr {
  let mut out = blst_fr::default();
  unsafe { blst_fr_from_scalar(&mut out, scalar) };
  out
}

pub(crate) fn fr_from_uint64(value: &[u64; 4]) -> blst_fr {
  let mut out = blst_fr::default();
  unsafe { blst_fr_from_uint64(&mut out, value.as_ptr()) };
  out
}

pub(crate) fn fr_inverse(value: &blst_fr) -> blst_fr {
  let mut out = blst_fr::default();
  unsafe { blst_fr_inverse(&mut out, value) };
  out
}

pub(crate) fn fr_mul(a: &blst_fr, b: &blst_fr) -> blst_fr {
  let mut out = blst_fr::default();
  unsafe { blst_fr_mul(&mut out, a, b) };
  out
}

pub(crate) fn fr_sub(a: &blst_fr, b: &blst_fr) -> blst_fr {
  let mut out = blst_fr::default();
  unsafe { blst_fr_sub(&mut out, a, b) };
  out
}

pub(crate) fn p1_add_or_double(a: &blst_p1, b: &blst_p1) -> blst_p1 {
  let mut out = blst_p1::default();
  unsafe { blst_p1_add_or_double(&mut out, a, b) };
  out
}

pub(crate) fn p1_affine_compress(point: &blst_p1_affine) -> [u8; 48] {
  let mut out = [0u8; 48];
  unsafe { blst_p1_affine_compress(out.as_mut_ptr(), point) };
  out
}

pub(crate) fn p1_from_affine(point: &blst_p1_affine) -> blst_p1 {
  let mut out = blst_p1::default();
  unsafe { blst_p1_from_affine(&mut out, point) };
  out
}

pub(crate) fn p1_mult(point: &blst_p1_affine, scalar: &[u8], nbits: usize) -> blst_p1_affine {
  let proj = p1_from_affine(point);
  let mut out = blst_p1::default();
  unsafe { blst_p1_mult(&mut out, &proj, scalar.as_ptr(), nbits) };
  p1_to_affine(&out)
}

pub(crate) fn p1_to_affine(point: &blst_p1) -> blst_p1_affine {
  let mut aff = blst_p1_affine::default();
  unsafe { blst_p1_to_affine(&mut aff, point) };
  aff
}

pub(crate) fn p1_uncompress(bytes: &[u8; 48]) -> Result<blst_p1_affine, BLST_ERROR> {
  let mut aff = blst_p1_affine::default();
  let rc = unsafe { blst_p1_uncompress(&mut aff, bytes.as_ptr()) };
  if rc == BLST_ERROR::BLST_SUCCESS {
    Ok(aff)
  } else {
    Err(rc)
  }
}

pub(crate) fn p2_add_or_double(a: &blst_p2, b: &blst_p2) -> blst_p2 {
  let mut out = blst_p2::default();
  unsafe { blst_p2_add_or_double(&mut out, a, b) };
  out
}

pub(crate) fn p2_affine_compress(point: &blst_p2_affine) -> [u8; 96] {
  let mut out = [0u8; 96];
  unsafe { blst_p2_affine_compress(out.as_mut_ptr(), point) };
  out
}

pub(crate) fn p2_affine_serialize(point: &blst_p2_affine) -> [u8; 192] {
  let mut out = [0u8; 192];
  unsafe { blst_p2_affine_serialize(out.as_mut_ptr(), point) };
  out
}

pub(crate) fn p2_cneg(point: &blst_p2, flag: bool) -> blst_p2 {
  let mut out = *point;
  unsafe { blst_p2_cneg(&mut out, flag) };
  out
}

pub(crate) fn p2_double(point: &blst_p2) -> blst_p2 {
  let mut out = blst_p2::default();
  unsafe { blst_p2_double(&mut out, point) };
  out
}

pub(crate) fn p2_from_affine(point: &blst_p2_affine) -> blst_p2 {
  let mut out = blst_p2::default();
  unsafe { blst_p2_from_affine(&mut out, point) };
  out
}

pub(crate) fn p2_generator() -> blst_p2 {
  unsafe { *blst_p2_generator() }
}

pub(crate) fn p2_mult(point: &blst_p2, scalar: &[u8], nbits: usize) -> blst_p2 {
  let mut out = blst_p2::default();
  unsafe { blst_p2_mult(&mut out, point, scalar.as_ptr(), nbits) };
  out
}

pub(crate) fn p2_to_affine(point: &blst_p2) -> blst_p2_affine {
  let mut aff = blst_p2_affine::default();
  unsafe { blst_p2_to_affine(&mut aff, point) };
  aff
}

pub(crate) fn p2_uncompress(bytes: &[u8; 96]) -> Result<blst_p2_affine, BLST_ERROR> {
  let mut out = blst_p2_affine::default();
  let rc = unsafe { blst_p2_uncompress(&mut out, bytes.as_ptr()) };
  if rc == BLST_ERROR::BLST_SUCCESS {
    Ok(out)
  } else {
    Err(rc)
  }
}

pub(crate) fn pairings_equal_with_g1_generator(
  lhs_g2: &blst_p2_affine,
  rhs_g2: &blst_p2,
  rhs_g1: &blst_p1_affine,
) -> bool {
  let rhs_g2_aff = p2_to_affine(rhs_g2);
  let g1_generator = p1_affine_generator();
  let mut lhs = blst_fp12::default();
  let mut rhs = blst_fp12::default();
  unsafe {
    blst_miller_loop(&mut lhs, lhs_g2, &g1_generator);
    blst_miller_loop(&mut rhs, &rhs_g2_aff, rhs_g1);
    blst_fp12_finalverify(&lhs, &rhs)
  }
}

pub(crate) fn scalar_from_bendian(bytes: &[u8; 32]) -> blst_scalar {
  let mut scalar = blst_scalar::default();
  unsafe { blst_scalar_from_bendian(&mut scalar, bytes.as_ptr()) };
  scalar
}

pub(crate) fn scalar_from_fr(value: &blst_fr) -> blst_scalar {
  let mut out = blst_scalar::default();
  unsafe { blst_scalar_from_fr(&mut out, value) };
  out
}

pub(crate) fn sk_check(sk: &blst_scalar) -> bool {
  unsafe { blst_sk_check(sk) }
}

pub(crate) fn sk_to_pk2_in_g1(sk: &blst_scalar) -> blst_p1_affine {
  let mut aff = blst_p1_affine::default();
  unsafe { blst_sk_to_pk2_in_g1(core::ptr::null_mut(), &mut aff, sk) };
  aff
}
