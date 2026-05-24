//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Legacy serialization format for BLS elements.
//!
//! G1 (48 bytes): sign bit at byte[0] & 0x80, no compression indicator.
//! G2 (96 bytes): legacy component order (c0||c1), sign bit at byte[0] & 0x80.

use super::error::Error;

use blst::blst_p1_affine;
use blst::blst_p2_affine;
use blst::BLST_ERROR;
use hex_literal::hex;

/// Serialize a G1 affine point to 48 legacy bytes.
#[expect(unsafe_code, reason = "blst C FFI")]
pub(super) fn ser_g1(p: &blst_p1_affine) -> [u8; 48] {
  let mut ietf = [0u8; 48];
  unsafe { blst::blst_p1_affine_compress(ietf.as_mut_ptr(), p) };

  if ietf[0] & 0xc0 == 0xc0 {
    return ietf; // infinity is the same in both formats
  }

  // IETF: bit 7 = compression, bit 5 = sign.
  // Legacy: bit 7 = sign, no compression indicator.
  let sign = (ietf[0] >> 5) & 1;
  let mut legacy = ietf;
  legacy[0] &= 0x1f;
  if sign == 1 {
    legacy[0] |= 0x80;
  }
  legacy
}

/// Deserialize 48 legacy bytes to a G1 affine point.
#[expect(unsafe_code, reason = "blst C FFI")]
pub(super) fn deser_g1(bytes: &[u8; 48]) -> Result<blst_p1_affine, Error> {
  if bytes[0] & 0xc0 == 0xc0 {
    let mut out = blst_p1_affine::default();
    let rc = unsafe { blst::blst_p1_uncompress(&mut out, bytes.as_ptr()) };
    return if rc == BLST_ERROR::BLST_SUCCESS {
      Ok(out)
    } else {
      Err(Error::InvalidPublicKey)
    };
  }

  let sign = (bytes[0] >> 7) & 1;
  let mut ietf = *bytes;
  ietf[0] &= 0x7f;
  ietf[0] |= 0x80; // compression
  if sign == 1 {
    ietf[0] |= 0x20; // sign
  }

  let mut out = blst_p1_affine::default();
  let rc = unsafe { blst::blst_p1_uncompress(&mut out, ietf.as_ptr()) };
  if rc == BLST_ERROR::BLST_SUCCESS {
    Ok(out)
  } else {
    Err(Error::InvalidPublicKey)
  }
}

/// Serialize a G2 affine point to 96 legacy bytes.
///
/// Uses uncompressed 192-byte intermediate to sidestep sign-bit convention
/// differences between IETF and legacy formats.
///
/// blst:   `[x.c1(48), x.c0(48), y.c1(48), y.c0(48)]`
/// Legacy: `[x.c0(48), x.c1(48)]`, sign at byte\[0\] bit 7
#[expect(unsafe_code, reason = "blst C FFI")]
pub(super) fn ser_g2(p: &blst_p2_affine) -> [u8; 96] {
  let mut uncomp = [0u8; 192];
  unsafe { blst::blst_p2_affine_serialize(uncomp.as_mut_ptr(), p) };

  if uncomp.iter().all(|&b| b == 0) {
    let mut out = [0u8; 96];
    out[0] = 0xc0;
    return out;
  }

  let x_c1 = &uncomp[0..48];
  let x_c0 = &uncomp[48..96];
  let y_c1 = &uncomp[96..144];

  let sign = y_c1_is_larger(y_c1);

  let mut legacy = [0u8; 96];
  legacy[..48].copy_from_slice(x_c0);
  legacy[48..96].copy_from_slice(x_c1);
  if sign {
    legacy[0] |= 0x80;
  }
  legacy
}

/// Deserialize 96 legacy bytes to a G2 affine point.
#[expect(unsafe_code, reason = "blst C FFI")]
pub(super) fn deser_g2(bytes: &[u8; 96]) -> Result<blst_p2_affine, Error> {
  if bytes[0] & 0xc0 == 0xc0 {
    let mut ietf = [0u8; 96];
    ietf[0] = 0xc0;
    let mut out = blst_p2_affine::default();
    let rc = unsafe { blst::blst_p2_uncompress(&mut out, ietf.as_ptr()) };
    return if rc == BLST_ERROR::BLST_SUCCESS {
      Ok(out)
    } else {
      Err(Error::InvalidSignature)
    };
  }

  let sign = (bytes[0] >> 7) & 1;

  let mut x_c0 = [0u8; 48];
  x_c0.copy_from_slice(&bytes[..48]);
  x_c0[0] &= 0x7f; // clear sign bit
  let x_c1 = &bytes[48..96];

  let mut ietf = [0u8; 96];
  ietf[..48].copy_from_slice(x_c1);
  ietf[48..96].copy_from_slice(&x_c0);

  ietf[0] |= 0x80; // compression

  // Decompress with sign=0, then negate y if needed.
  let mut out = blst_p2_affine::default();
  let rc = unsafe { blst::blst_p2_uncompress(&mut out, ietf.as_ptr()) };
  if rc != BLST_ERROR::BLST_SUCCESS {
    return Err(Error::InvalidSignature);
  }

  let mut y_c1_bytes = [0u8; 48];
  unsafe { blst_bendian_from_fp(y_c1_bytes.as_mut_ptr(), &out.y.fp[1]) };
  let decompressed_sign = y_c1_is_larger(&y_c1_bytes);

  if (sign == 1) != decompressed_sign {
    let neg_y = fp2_neg(&out.y);
    out.y = neg_y;
  }

  Ok(out)
}

/// y.c1 > (p-1)/2, matching the legacy sign convention.
fn y_c1_is_larger(y_c1: &[u8]) -> bool {
  const HALF_P: [u8; 48] = hex!(
    "0d0088f5 1cbff34d 258dd3db 21a5d66b"
    "b23ba5c2 79c2895f b3986950 7b587b12"
    "0f55ffff 58a9ffff dcff7fff ffffd555"
  );

  y_c1.len() >= 48 && y_c1[..48] > HALF_P[..]
}

#[expect(unsafe_code, reason = "blst C FFI")]
fn fp2_neg(a: &blst::blst_fp2) -> blst::blst_fp2 {
  let mut out = blst::blst_fp2::default();
  unsafe { blst::blst_fp2_cneg(&mut out, a, true) };
  out
}

extern "C" {
  fn blst_bendian_from_fp(out: *mut u8, a: *const blst::blst_fp);
}
