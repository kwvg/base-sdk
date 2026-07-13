//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Shallue-van de Woestijne hash-to-G2 for legacy BLS.

use super::blst_ffi::{self, Fp, Fp2};

use blst::{blst_p2, blst_p2_affine};
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
fn curve_b() -> Fp2 {
  Fp2::new(Fp::from_u64(4), Fp::from_u64(4))
}

/// Hash a 32-byte message to a G2 point using the legacy Dash algorithm.
pub(crate) fn hash_to_g2(msg: &[u8; 32]) -> blst_p2 {
  // Step 1: derive four field elements via SHA-256 with domain prefixes.
  let t00 = hash_to_fp(msg, b"G2_0_c0");
  let t01 = hash_to_fp(msg, b"G2_0_c1");
  let t10 = hash_to_fp(msg, b"G2_1_c0");
  let t11 = hash_to_fp(msg, b"G2_1_c1");

  // Step 2: form two Fp2 elements.
  let t0 = Fp2::new(t00, t01);
  let t1 = Fp2::new(t10, t11);

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
  let t0 = blst_ffi::p2_cneg(&blst_ffi::p2_mult(p, &BLS_X_LE, BLS_X_BITS), true);

  // t1 = x²·P = x·t0
  let t1 = blst_ffi::p2_cneg(&blst_ffi::p2_mult(&t0, &BLS_X_LE, BLS_X_BITS), true);

  // t2 = (x^2 - x - 1)*P = t1 - t0 - P
  let neg_t0 = blst_ffi::p2_cneg(&t0, true);
  let neg_p = blst_ffi::p2_cneg(p, true);
  let mut t2 = blst_ffi::p2_add_or_double(&t1, &neg_t0);
  t2 = blst_ffi::p2_add_or_double(&t2, &neg_p);

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
  let x = Fp2::from_raw(p.x).with_c1(-Fp::from_raw(p.x.fp[1]));
  let y = Fp2::from_raw(p.y).with_c1(-Fp::from_raw(p.y.fp[1]));

  // Multiply by the Frobenius coefficients.
  let psi_x = psi_coeff_x();
  let psi_y = psi_coeff_y();
  let rx = x * psi_x;
  let ry = y * psi_y;

  blst_p2_affine {
    x: rx.into_raw(),
    y: ry.into_raw(),
  }
}

fn psi_coeff_x() -> Fp2 {
  // PSI_COEFF_X = (0, PSI_COEFF_X_C1)
  Fp2::new(Fp::zero(), Fp::from_bendian(&PSI_COEFF_X_C1))
}

fn psi_coeff_y() -> Fp2 {
  Fp2::new(Fp::from_bendian(&PSI_COEFF_Y_C0), Fp::from_bendian(&PSI_COEFF_Y_C1))
}

/// Hash `msg || tag || suffix` with SHA-256 twice (suffix=0 then suffix=1),
/// concatenate to 64 bytes, reduce mod p to produce an Fp element.
fn hash_to_fp(msg: &[u8; 32], tag: &[u8; 7]) -> Fp {
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
fn reduce_mod_p(wide: &[u8; 64]) -> Fp {
  let mut lo_bytes = [0u8; 48];
  lo_bytes.copy_from_slice(&wide[16..]);
  let lo_fp = Fp::from_bendian(&lo_bytes);

  let mut hi_bytes = [0u8; 48];
  hi_bytes[32..48].copy_from_slice(&wide[..16]);
  let hi_fp = Fp::from_bendian(&hi_bytes);
  let r_fp = Fp::from_bendian(&R_MOD_P);

  // result = hi * R + lo
  hi_fp * r_fp + lo_fp
}

/// Shallue-van de Woestijne encoding from Fp2 to G2 (not cofactor-cleared).
fn sw_encode(t: &Fp2) -> blst_p2 {
  if t.is_zero() {
    return blst_p2::default();
  }

  let b = curve_b();
  let one = Fp::from_u64(1);

  let nt = -*t;
  let parity = t.c1_bendian() > nt.c1_bendian();

  // w = t^2 + b + 1
  let mut w = t.square() + b;
  w = w.with_c0(w.c0() + one);

  if w.is_zero() {
    let mut g = blst_ffi::p2_generator();
    if parity {
      g = blst_ffi::p2_cneg(&g, true);
    }
    return g;
  }

  let s3_fp2 = Fp2::from(Fp::from_bendian(&S3));
  let s32_fp2 = Fp2::from(Fp::from_bendian(&S32));

  // w = sqrt(-3) * t / (t^2 + b + 1)
  w = w.inverse();
  let tmp = s3_fp2 * *t;
  w = w * tmp;

  // x1 = -w*t + (sqrt(-3) - 1) / 2
  let x1 = -(w * *t) + s32_fp2;

  // x2 = -x1 - 1
  let mut x2 = -x1;
  x2 = x2.with_c0(x2.c0() - one);

  // x3 = 1/w^2 + 1
  let mut x3 = w.square().inverse();
  x3 = x3.with_c0(x3.c0() + one);

  let rhs1 = curve_rhs(&x1);
  let rhs2 = curve_rhs(&x2);

  let has_y1 = rhs1.sqrt().is_some();
  let has_y2 = rhs2.sqrt().is_some();

  let xx1: i32 = if has_y1 { 1 } else { -1 };
  let xx2: i32 = if has_y2 { 1 } else { -1 };
  let index = (((xx1 - 1) * xx2) % 3 + 3) % 3;

  let (x, mut y) = if index == 0 {
    let rhs = curve_rhs(&x1);
    let y = rhs.sqrt().unwrap_or_else(Fp2::zero);
    (x1, y)
  } else if index == 1 {
    let rhs = curve_rhs(&x2);
    let y = rhs.sqrt().unwrap_or_else(Fp2::zero);
    (x2, y)
  } else {
    let rhs = curve_rhs(&x3);
    let y = rhs.sqrt().unwrap_or_else(Fp2::zero);
    (x3, y)
  };

  let ny = -y;
  let y_parity = y.c1_bendian() > ny.c1_bendian();
  if y_parity != parity {
    y = ny;
  }

  let aff = blst_p2_affine {
    x: x.into_raw(),
    y: y.into_raw(),
  };
  blst_ffi::p2_from_affine(&aff)
}

/// x^3 + b
fn curve_rhs(x: &Fp2) -> Fp2 {
  let b = curve_b();
  let x2 = x.square();
  let x3 = x2 * *x;
  x3 + b
}
