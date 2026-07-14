//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Bridging routines for unsafe blst FFI operations.

use crate::prelude::Vec;

use blst::*;
use core::ops::{Add, Mul, Neg, Sub};
use core::ptr::null_mut;
use rand_core::CryptoRngCore;
use zeroize::{Zeroize, Zeroizing};

/// Bit-length for scalars known to be reduced mod q (< 2^255).
pub(crate) const FR_BITS: usize = 255;

/// Bit-length for unreduced 256-bit scalars.
pub(crate) const SCALAR_BITS: usize = 256;

extern "C" {
  fn blst_p2_generator() -> *const blst_p2;
  fn blst_fp_add(ret: *mut blst_fp, a: *const blst_fp, b: *const blst_fp);
  fn blst_fp_sub(ret: *mut blst_fp, a: *const blst_fp, b: *const blst_fp);
  fn blst_fp_mul(ret: *mut blst_fp, a: *const blst_fp, b: *const blst_fp);
  fn blst_bendian_from_fp(out: *mut u8, a: *const blst_fp);
  fn blst_p1_affine_is_inf(p: *const blst_p1_affine) -> bool;
  fn blst_p2_affine_is_inf(p: *const blst_p2_affine) -> bool;
  fn blst_p1_affine_in_g1(p: *const blst_p1_affine) -> bool;
  fn blst_p2_affine_in_g2(p: *const blst_p2_affine) -> bool;
  fn blst_p1_affine_generator() -> *const blst_p1_affine;
  fn blst_scalar_fr_check(a: *const blst_scalar) -> bool;
  fn blst_sk_check(sk: *const blst_scalar) -> bool;
}

fn p1_affine_generator() -> blst_p1_affine {
  unsafe { *blst_p1_affine_generator() }
}

pub(crate) fn bendian_from_scalar(scalar: &blst_scalar) -> [u8; 32] {
  let mut out = [0u8; 32];
  unsafe { blst_bendian_from_scalar(out.as_mut_ptr(), scalar) };
  out
}

pub(crate) fn p1_affine_compress(point: &blst_p1_affine) -> [u8; 48] {
  let mut out = [0u8; 48];
  unsafe { blst_p1_affine_compress(out.as_mut_ptr(), point) };
  out
}

pub(crate) fn p1_affine_in_g1(point: &blst_p1_affine) -> bool {
  unsafe { blst_p1_affine_in_g1(point) }
}

pub(crate) fn p1_affine_is_inf(point: &blst_p1_affine) -> bool {
  unsafe { blst_p1_affine_is_inf(point) }
}

pub(crate) fn p1_from_affine(point: &blst_p1_affine) -> blst_p1 {
  let mut out = blst_p1::default();
  unsafe { blst_p1_from_affine(&mut out, point) };
  out
}

pub(crate) fn p1_mult(point: &blst_p1_affine, scalar: &[u8], nbits: usize) -> blst_p1_affine {
  let proj = p1_from_affine(point);
  p1_to_affine(&p1_mult_projective(&proj, scalar, nbits))
}

pub(crate) fn p1_mult_projective(point: &blst_p1, scalar: &[u8], nbits: usize) -> blst_p1 {
  let mut out = blst_p1::default();
  unsafe { blst_p1_mult(&mut out, point, scalar.as_ptr(), nbits) };
  out
}

pub(crate) fn p1_to_affine(point: &blst_p1) -> blst_p1_affine {
  let mut aff = blst_p1_affine::default();
  unsafe { blst_p1_to_affine(&mut aff, point) };
  aff
}

pub(crate) fn p1_affine_serialize(point: &blst_p1_affine) -> [u8; 96] {
  let mut out = [0u8; 96];
  unsafe { blst_p1_affine_serialize(out.as_mut_ptr(), point) };
  out
}

/// Deserialize an uncompressed G1 point. On-curve check only (no
/// square root and no subgroup check), so this is much cheaper
/// than `p1_uncompress`.
pub(crate) fn p1_deserialize(bytes: &[u8; 96]) -> Result<blst_p1_affine, BLST_ERROR> {
  let mut aff = blst_p1_affine::default();
  let rc = unsafe { blst_p1_deserialize(&mut aff, bytes.as_ptr()) };
  if rc == BLST_ERROR::BLST_SUCCESS {
    Ok(aff)
  } else {
    Err(rc)
  }
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

pub(crate) fn p1s_add(points: &[blst_p1_affine]) -> blst_p1_affine {
  p1_to_affine(&points.add())
}

pub(crate) fn p1s_mult_pippenger(points: &[blst_p1_affine], scalars: &[u8], nbits: usize) -> blst_p1_affine {
  p1_to_affine(&points.mult(scalars, nbits))
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

pub(crate) fn p2_affine_in_g2(point: &blst_p2_affine) -> bool {
  unsafe { blst_p2_affine_in_g2(point) }
}

pub(crate) fn p2_affine_is_inf(point: &blst_p2_affine) -> bool {
  unsafe { blst_p2_affine_is_inf(point) }
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

pub(crate) fn p2s_add(points: &[blst_p2_affine]) -> blst_p2_affine {
  p2_to_affine(&points.add())
}

pub(crate) fn p2s_mult_pippenger(points: &[blst_p2_affine], scalars: &[u8], nbits: usize) -> blst_p2_affine {
  p2_to_affine(&points.mult(scalars, nbits))
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

pub(crate) fn scalar_fr_check(scalar: &blst_scalar) -> bool {
  unsafe { blst_scalar_fr_check(scalar) }
}

pub(crate) fn scalar_from_bendian(bytes: &[u8; 32]) -> blst_scalar {
  let mut scalar = blst_scalar::default();
  unsafe { blst_scalar_from_bendian(&mut scalar, bytes.as_ptr()) };
  scalar
}

pub(crate) fn sign_pk2_in_g1(sk: &blst_scalar, hash: &blst_p2) -> blst_p2_affine {
  let mut aff = blst_p2_affine::default();
  unsafe { blst_sign_pk2_in_g1(core::ptr::null_mut(), &mut aff, hash, sk) };
  aff
}

pub(crate) fn sk_check(sk: &blst_scalar) -> bool {
  unsafe { blst_sk_check(sk) }
}

pub(crate) fn sk_to_pk2_in_g1(sk: &blst_scalar) -> blst_p1_affine {
  let mut aff = blst_p1_affine::default();
  unsafe { blst_sk_to_pk2_in_g1(null_mut(), &mut aff, sk) };
  aff
}

#[derive(Clone, Copy, Default, Eq, PartialEq)]
pub(crate) struct Fr(blst_fr);

impl Fr {
  pub(crate) fn one() -> Self {
    let mut out = blst_fr::default();
    let one = [1u64, 0, 0, 0];
    unsafe { blst_fr_from_uint64(&mut out, one.as_ptr()) };
    Self(out)
  }

  pub(crate) fn from_scalar(scalar: &blst_scalar) -> Self {
    let mut out = blst_fr::default();
    unsafe { blst_fr_from_scalar(&mut out, scalar) };
    Self(out)
  }

  pub(crate) fn from_bendian_scalar(bytes: &[u8; 32]) -> Self {
    Self::from_scalar(&scalar_from_bendian(bytes))
  }

  pub(crate) fn random(rng: &mut impl CryptoRngCore) -> Self {
    let mut bytes = Zeroizing::new([0u8; 32]);
    loop {
      rng.fill_bytes(&mut *bytes);
      let mut scalar = scalar_from_bendian(&bytes);
      if scalar_fr_check(&scalar) {
        let out = Self::from_scalar(&scalar);
        scalar.zeroize();
        return out;
      }
      scalar.zeroize();
    }
  }

  pub(crate) fn to_scalar(self) -> blst_scalar {
    let mut out = blst_scalar::default();
    unsafe { blst_scalar_from_fr(&mut out, &self.0) };
    out
  }

  pub(crate) fn inverse(self) -> Self {
    let mut out = blst_fr::default();
    unsafe { blst_fr_inverse(&mut out, &self.0) };
    Self(out)
  }

  pub(crate) fn append_scalar_le(self, out: &mut Vec<u8>) {
    let mut scalar = self.to_scalar();
    out.extend_from_slice(&scalar.b);
    scalar.zeroize();
  }
}

impl Add for Fr {
  type Output = Self;

  fn add(self, rhs: Self) -> Self::Output {
    let mut out = blst_fr::default();
    unsafe { blst_fr_add(&mut out, &self.0, &rhs.0) };
    Self(out)
  }
}

impl Mul for Fr {
  type Output = Self;

  fn mul(self, rhs: Self) -> Self::Output {
    let mut out = blst_fr::default();
    unsafe { blst_fr_mul(&mut out, &self.0, &rhs.0) };
    Self(out)
  }
}

impl Neg for Fr {
  type Output = Self;

  fn neg(self) -> Self::Output {
    let mut out = blst_fr::default();
    unsafe { blst_fr_cneg(&mut out, &self.0, true) };
    Self(out)
  }
}

impl Sub for Fr {
  type Output = Self;

  fn sub(self, rhs: Self) -> Self::Output {
    let mut out = blst_fr::default();
    unsafe { blst_fr_sub(&mut out, &self.0, &rhs.0) };
    Self(out)
  }
}

impl Zeroize for Fr {
  fn zeroize(&mut self) {
    self.0.l.zeroize();
  }
}

#[derive(Clone, Copy, Default, Eq, PartialEq)]
pub(crate) struct Fp(blst_fp);

impl Fp {
  pub(crate) fn zero() -> Self {
    Self(blst_fp::default())
  }

  pub(crate) fn from_raw(raw: blst_fp) -> Self {
    Self(raw)
  }

  pub(crate) fn into_raw(self) -> blst_fp {
    self.0
  }

  pub(crate) fn from_bendian(bytes: &[u8; 48]) -> Self {
    let mut out = blst_fp::default();
    unsafe { blst_fp_from_bendian(&mut out, bytes.as_ptr()) };
    Self(out)
  }

  pub(crate) fn from_u64(v: u64) -> Self {
    let mut bytes = [0u8; 48];
    bytes[40..48].copy_from_slice(&v.to_be_bytes());
    Self::from_bendian(&bytes)
  }

  pub(crate) fn to_bendian(self) -> [u8; 48] {
    let mut out = [0u8; 48];
    unsafe { blst_bendian_from_fp(out.as_mut_ptr(), &self.0) };
    out
  }

  pub(crate) fn cneg(self, flag: bool) -> Self {
    let mut out = blst_fp::default();
    unsafe { blst_fp_cneg(&mut out, &self.0, flag) };
    Self(out)
  }
}

impl Add for Fp {
  type Output = Self;

  fn add(self, rhs: Self) -> Self::Output {
    let mut out = blst_fp::default();
    unsafe { blst_fp_add(&mut out, &self.0, &rhs.0) };
    Self(out)
  }
}

impl Mul for Fp {
  type Output = Self;

  fn mul(self, rhs: Self) -> Self::Output {
    let mut out = blst_fp::default();
    unsafe { blst_fp_mul(&mut out, &self.0, &rhs.0) };
    Self(out)
  }
}

impl Neg for Fp {
  type Output = Self;

  fn neg(self) -> Self::Output {
    self.cneg(true)
  }
}

impl Sub for Fp {
  type Output = Self;

  fn sub(self, rhs: Self) -> Self::Output {
    let mut out = blst_fp::default();
    unsafe { blst_fp_sub(&mut out, &self.0, &rhs.0) };
    Self(out)
  }
}

#[derive(Clone, Copy, Default, Eq, PartialEq)]
pub(crate) struct Fp2(blst_fp2);

impl Fp2 {
  pub(crate) fn zero() -> Self {
    Self(blst_fp2::default())
  }

  pub(crate) fn new(c0: Fp, c1: Fp) -> Self {
    Self(blst_fp2 {
      fp: [c0.into_raw(), c1.into_raw()],
    })
  }

  pub(crate) fn from_raw(raw: blst_fp2) -> Self {
    Self(raw)
  }

  pub(crate) fn into_raw(self) -> blst_fp2 {
    self.0
  }

  pub(crate) fn from_fp(fp: Fp) -> Self {
    Self::new(fp, Fp::zero())
  }

  pub(crate) fn c0(self) -> Fp {
    Fp::from_raw(self.0.fp[0])
  }

  pub(crate) fn c1(self) -> Fp {
    Fp::from_raw(self.0.fp[1])
  }

  pub(crate) fn with_c0(mut self, c0: Fp) -> Self {
    self.0.fp[0] = c0.into_raw();
    self
  }

  pub(crate) fn with_c1(mut self, c1: Fp) -> Self {
    self.0.fp[1] = c1.into_raw();
    self
  }

  pub(crate) fn is_zero(self) -> bool {
    self.0.fp[0].l == [0u64; 6] && self.0.fp[1].l == [0u64; 6]
  }

  pub(crate) fn square(self) -> Self {
    let mut out = blst_fp2::default();
    unsafe { blst_fp2_sqr(&mut out, &self.0) };
    Self(out)
  }

  pub(crate) fn inverse(self) -> Self {
    let mut out = blst_fp2::default();
    unsafe { blst_fp2_inverse(&mut out, &self.0) };
    Self(out)
  }

  pub(crate) fn sqrt(self) -> Option<Self> {
    let mut out = blst_fp2::default();
    unsafe { blst_fp2_sqrt(&mut out, &self.0) }.then_some(Self(out))
  }

  pub(crate) fn c1_bendian(self) -> [u8; 48] {
    self.c1().to_bendian()
  }

  pub(crate) fn cneg(self, flag: bool) -> Self {
    let mut out = blst_fp2::default();
    unsafe { blst_fp2_cneg(&mut out, &self.0, flag) };
    Self(out)
  }
}

impl Add for Fp2 {
  type Output = Self;

  fn add(self, rhs: Self) -> Self::Output {
    let mut out = blst_fp2::default();
    unsafe { blst_fp2_add(&mut out, &self.0, &rhs.0) };
    Self(out)
  }
}

impl From<Fp> for Fp2 {
  fn from(fp: Fp) -> Self {
    Self::from_fp(fp)
  }
}

impl Mul for Fp2 {
  type Output = Self;

  fn mul(self, rhs: Self) -> Self::Output {
    let mut out = blst_fp2::default();
    unsafe { blst_fp2_mul(&mut out, &self.0, &rhs.0) };
    Self(out)
  }
}

impl Neg for Fp2 {
  type Output = Self;

  fn neg(self) -> Self::Output {
    self.cneg(true)
  }
}

impl Sub for Fp2 {
  type Output = Self;

  fn sub(self, rhs: Self) -> Self::Output {
    let mut out = blst_fp2::default();
    unsafe { blst_fp2_sub(&mut out, &self.0, &rhs.0) };
    Self(out)
  }
}
