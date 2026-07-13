//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Shallue-van de Woestijne hash-to-G2 for legacy BLS.

use crate::bls::blst_ffi;

use blst::{blst_fp, blst_fp2, blst_p2, blst_p2_affine};
use hex_literal::hex;
use sha2::{Digest, Sha256};

// sqrt(-3) mod p (big-endian, 48 bytes, left-padded from 40-byte hex
// B12_P381_S3).
const S3: [u8; 48] = hex!(
  "00000000 00000000 be32ce5f beed9ca3"
  "74d38c0e d41eefd5 bb675277 cdf12d11"
  "bc2fb026 c4140004 5c03ffff fffdfffd"
);

// (sqrt(-3) - 1) / 2 mod p (big-endian, 48 bytes, left-padded from 40-byte hex
// B12_P381_S32).
const S32: [u8; 48] = hex!(
  "00000000 00000000 5f19672f df76ce51"
  "ba69c607 6a0f77ea ddb3a93b e6f89688"
  "de17d813 620a0002 2e01ffff fffefffe"
);

// BLS12-381 curve parameter |x| in little-endian byte order.
// x = -(2^63 + 2^62 + 2^60 + 2^57 + 2^48 + 2^16)
// |x| = 0xD201000000010000
const BLS_X_LE: [u8; 8] = hex!("00000100 000001d2");
const BLS_X_BITS: usize = 64;

// Frobenius endomorphism constants for the BLS12-381 M-type twist.
// psi(x,y) = (conj(x)*PSI_COEFF_X, conj(y)*PSI_COEFF_Y)

// PSI_COEFF_X = (0, 0x1a0111ea397fe699ec02408663d4de85aa0d857d89759ad4
//                   897d29650fb85f9b409427eb4f49fffd8bfd00000000aaad)
const PSI_COEFF_X_C1: [u8; 48] = hex!(
  "1a0111ea 397fe699 ec024086 63d4de85"
  "aa0d857d 89759ad4 897d2965 0fb85f9b"
  "409427eb 4f49fffd 8bfd0000 0000aaad"
);

// PSI_COEFF_Y.c0
const PSI_COEFF_Y_C0: [u8; 48] = hex!(
  "135203e6 0180a68e e2e9c448 d77a2cd9"
  "1c3dedd9 30b1cf60 ef396489 f61eb45e"
  "304466cf 3e67fa0a f1ee7b04 121bdea2"
);

// PSI_COEFF_Y.c1
const PSI_COEFF_Y_C1: [u8; 48] = hex!(
  "06af0e04 37ff400b 6831e36d 6bd17ffe"
  "48395dab c2d3435e 77f76e17 009241c5"
  "ee67992f 72ec05f4 c81084fb ede3cc09"
);

// 2^384 mod p for BLS12-381 (big-endian, 48 bytes). Used in wide reduction.
const R_MOD_P: [u8; 48] = hex!(
  "15f65ec3 fa80e493 5c071a97 a256ec6d"
  "77ce5853 70525745 5f489857 53c758ba"
  "ebf4000b c40c0002 76090000 0002fffd"
);

// The 'b' coefficient for BLS12-381 twist curve: y^2 = x^3 + 4(1+i).
fn curve_b() -> blst_fp2 {
  blst_fp2 {
    fp: [fp_from_u64(4), fp_from_u64(4)],
  }
}

/// Hash a 32-byte message to a G2 point using the legacy Dash algorithm.
pub(super) fn hash_to_g2(msg: &[u8; 32]) -> blst_p2 {
  // Step 1: derive four field elements via SHA-256 with domain prefixes.
  let t00 = hash_to_fp(msg, b"G2_0_c0");
  let t01 = hash_to_fp(msg, b"G2_0_c1");
  let t10 = hash_to_fp(msg, b"G2_1_c0");
  let t11 = hash_to_fp(msg, b"G2_1_c1");

  // Step 2: form two Fp2 elements.
  let t0 = blst_fp2 { fp: [t00, t01] };
  let t1 = blst_fp2 { fp: [t10, t11] };

  // Step 3: apply Shallue-van de Woestijne encoding to each.
  let p0 = sw_encode(&t0);
  let p1 = sw_encode(&t1);

  // Step 4: add the two points.
  let sum = blst_ffi::p2_add_or_double(&p0, &p1);

  // Step 5: clear the cofactor via Budroni-Pintore.
  mul_cof_b12(&sum)
}

/// Cofactor clearing via the Budroni-Pintore method.
///
/// Computes `(x^2-x-1)*P + psi((x-1)*P) + psi^2(2*P)`
/// where `x` is the BLS12-381 curve parameter and `psi`
/// is the Frobenius endomorphism on the twist.
fn mul_cof_b12(p: &blst_p2) -> blst_p2 {
  // t0 = x·P  (x is negative, so negate after multiplying by |x|)
  let mut t0 = blst_ffi::p2_mult(p, &BLS_X_LE, BLS_X_BITS);
  t0 = blst_ffi::p2_cneg(&t0, true); // x is negative

  // t1 = x²·P = x·t0
  let mut t1 = blst_ffi::p2_mult(&t0, &BLS_X_LE, BLS_X_BITS);
  t1 = blst_ffi::p2_cneg(&t1, true); // x is negative

  // t2 = (x^2 - x - 1)*P = t1 - t0 - P
  let neg_t0 = blst_ffi::p2_cneg(&t0, true);
  let mut t2 = blst_ffi::p2_add_or_double(&t1, &neg_t0); // t1 - t0
  let neg_p = blst_ffi::p2_cneg(p, true);
  t2 = blst_ffi::p2_add_or_double(&t2, &neg_p); // - P

  // t3 = psi((x - 1)*P) = psi(t0 - P)
  let mut t3 = blst_ffi::p2_add_or_double(&t0, &neg_p); // t0 - P
                                                        // Normalize to affine for the psi map, then back.
  let t3_aff = psi(&blst_ffi::p2_to_affine(&t3));
  t3 = blst_ffi::p2_from_affine(&t3_aff);

  // t2 += t3
  t2 = blst_ffi::p2_add_or_double(&t2, &t3);

  // t3 = psi^2(2*P)
  let dbl_p = blst_ffi::p2_double(p);
  let psi1 = psi(&blst_ffi::p2_to_affine(&dbl_p));
  let psi2 = psi(&psi1);
  t3 = blst_ffi::p2_from_affine(&psi2);

  // result = t2 + t3
  blst_ffi::p2_add_or_double(&t2, &t3)
}

/// Frobenius endomorphism psi on E'(Fp2).
///
/// `psi(x, y) = (conj(x) * PSI_COEFF_X, conj(y) * PSI_COEFF_Y)`
///
/// where `conj(a + b*u) = a - b*u`.
fn psi(p: &blst_p2_affine) -> blst_p2_affine {
  // Conjugate x and y (negate the c1 component of each).
  let mut x = p.x;
  x.fp[1] = blst_ffi::fp_cneg(&x.fp[1], true);
  let mut y = p.y;
  y.fp[1] = blst_ffi::fp_cneg(&y.fp[1], true);

  // Multiply by the Frobenius coefficients.
  let psi_x = psi_coeff_x();
  let psi_y = psi_coeff_y();
  let rx = blst_ffi::fp2_mul(&x, &psi_x);
  let ry = blst_ffi::fp2_mul(&y, &psi_y);

  blst_p2_affine { x: rx, y: ry }
}

fn psi_coeff_x() -> blst_fp2 {
  // PSI_COEFF_X = (0, PSI_COEFF_X_C1)
  let c1 = blst_ffi::fp_from_bendian(&PSI_COEFF_X_C1);
  blst_fp2 {
    fp: [blst_fp::default(), c1],
  }
}

fn psi_coeff_y() -> blst_fp2 {
  let c0 = blst_ffi::fp_from_bendian(&PSI_COEFF_Y_C0);
  let c1 = blst_ffi::fp_from_bendian(&PSI_COEFF_Y_C1);
  blst_fp2 { fp: [c0, c1] }
}

/// Hash `msg || tag || suffix` with SHA-256 twice (suffix=0 then suffix=1),
/// concatenate to 64 bytes, reduce mod p to produce an Fp element.
fn hash_to_fp(msg: &[u8; 32], tag: &[u8; 7]) -> blst_fp {
  let mut input = [0u8; 40];
  input[..32].copy_from_slice(msg);
  input[32..39].copy_from_slice(tag);

  input[39] = 0;
  let h0 = Sha256::digest(input);

  input[39] = 1;
  let h1 = Sha256::digest(input);

  let mut wide = [0u8; 64];
  wide[..32].copy_from_slice(&h0);
  wide[32..].copy_from_slice(&h1);

  reduce_mod_p(&wide)
}

/// Reduce a 64-byte big-endian integer mod p to Fp.
///
/// Splits into `hi * 2^384 + lo`, computes `hi * R + lo` where
/// `R = 2^384 mod p`.
fn reduce_mod_p(wide: &[u8; 64]) -> blst_fp {
  let lo_fp = blst_ffi::fp_from_bendian(wide[16..].try_into().expect("48-byte slice"));

  let mut hi_bytes = [0u8; 48];
  hi_bytes[32..48].copy_from_slice(&wide[..16]);
  let hi_fp = blst_ffi::fp_from_bendian(&hi_bytes);

  let r_fp = blst_ffi::fp_from_bendian(&R_MOD_P);

  // result = hi * R + lo
  let tmp = blst_ffi::fp_mul(&hi_fp, &r_fp);
  blst_ffi::fp_add(&tmp, &lo_fp)
}

/// Shallue-van de Woestijne encoding from Fp2 to G2 (not cofactor-cleared).
fn sw_encode(t: &blst_fp2) -> blst_p2 {
  if fp2_is_zero(t) {
    return blst_p2::default();
  }

  let b = curve_b();
  let one = fp_from_u64(1);

  let nt = fp2_neg(t);
  let parity = fp2_cmp_c1(t) > fp2_cmp_c1(&nt);

  // w = t^2 + b + 1
  let mut w = blst_ffi::fp2_add(&blst_ffi::fp2_sqr(t), &b);
  w.fp[0] = blst_ffi::fp_add(&w.fp[0], &one);

  if fp2_is_zero(&w) {
    let mut g = blst_ffi::p2_generator();
    if parity {
      g = blst_ffi::p2_cneg(&g, true);
    }
    return g;
  }

  let s3_fp2 = fp2_from_fp(&fp_from_bytes(&S3));
  let s32_fp2 = fp2_from_fp(&fp_from_bytes(&S32));

  // w = sqrt(-3) * t / (t^2 + b + 1)
  w = blst_ffi::fp2_inverse(&w);
  let tmp = blst_ffi::fp2_mul(&s3_fp2, t);
  w = blst_ffi::fp2_mul(&w, &tmp);

  // x1 = -w*t + (sqrt(-3) - 1) / 2
  let mut x1 = fp2_neg(&blst_ffi::fp2_mul(&w, t));
  x1 = blst_ffi::fp2_add(&x1, &s32_fp2);

  // x2 = -x1 - 1
  let mut x2 = fp2_neg(&x1);
  x2.fp[0] = blst_ffi::fp_sub(&x2.fp[0], &one);

  // x3 = 1/w^2 + 1
  let mut x3 = blst_ffi::fp2_inverse(&blst_ffi::fp2_sqr(&w));
  x3.fp[0] = blst_ffi::fp_add(&x3.fp[0], &one);

  let rhs1 = curve_rhs(&x1);
  let rhs2 = curve_rhs(&x2);

  let has_y1 = blst_ffi::fp2_sqrt(&rhs1).is_some();
  let has_y2 = blst_ffi::fp2_sqrt(&rhs2).is_some();

  let xx1: i32 = if has_y1 { 1 } else { -1 };
  let xx2: i32 = if has_y2 { 1 } else { -1 };
  let index = (((xx1 - 1) * xx2) % 3 + 3) % 3;

  let (x, mut y) = if index == 0 {
    let rhs = curve_rhs(&x1);
    let y = blst_ffi::fp2_sqrt(&rhs).expect("selected square root");
    (x1, y)
  } else if index == 1 {
    let rhs = curve_rhs(&x2);
    let y = blst_ffi::fp2_sqrt(&rhs).expect("selected square root");
    (x2, y)
  } else {
    let rhs = curve_rhs(&x3);
    let y = blst_ffi::fp2_sqrt(&rhs).expect("selected square root");
    (x3, y)
  };

  let ny = fp2_neg(&y);
  let y_parity = fp2_cmp_c1(&y) > fp2_cmp_c1(&ny);
  if y_parity != parity {
    y = ny;
  }

  let aff = blst_p2_affine { x, y };
  blst_ffi::p2_from_affine(&aff)
}

fn fp_from_bytes(bytes: &[u8; 48]) -> blst_fp {
  blst_ffi::fp_from_bendian(bytes)
}

fn fp_from_u64(v: u64) -> blst_fp {
  let mut buf = [0u8; 48];
  buf[40..48].copy_from_slice(&v.to_be_bytes());
  blst_ffi::fp_from_bendian(&buf)
}

fn fp2_from_fp(fp: &blst_fp) -> blst_fp2 {
  blst_fp2 {
    fp: [*fp, blst_fp::default()],
  }
}

fn fp2_is_zero(a: &blst_fp2) -> bool {
  a.fp[0].l == [0u64; 6] && a.fp[1].l == [0u64; 6]
}

fn fp2_neg(a: &blst_fp2) -> blst_fp2 {
  blst_ffi::fp2_cneg(a, true)
}

/// Imaginary component as big-endian bytes for lexicographic comparison.
fn fp2_cmp_c1(a: &blst_fp2) -> [u8; 48] {
  blst_ffi::bendian_from_fp(&a.fp[1])
}

/// x^3 + b
fn curve_rhs(x: &blst_fp2) -> blst_fp2 {
  let b = curve_b();
  let x2 = blst_ffi::fp2_sqr(x);
  let x3 = blst_ffi::fp2_mul(&x2, x);
  blst_ffi::fp2_add(&x3, &b)
}
