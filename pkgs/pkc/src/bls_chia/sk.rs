//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Legacy BLS secret key.

use super::error::Error;
use super::hash;
use super::pk::PublicKey;
use super::sig::Signature;

use blst::*;
use zeroize::Zeroize;

use core::fmt;

/// A legacy BLS secret key (32-byte scalar).
#[derive(Clone)]
pub struct SecretKey(blst_scalar);

impl SecretKey {
  /// Derive a secret key from input keying material (>= 32 bytes). Uses the
  /// same IETF key generation as standard BLS, only the signing scheme
  /// differs.
  pub fn generate(ikm: &[u8]) -> Result<Self, Error> {
    let sk = blst::min_pk::SecretKey::key_gen(ikm, &[]).map_err(|_| Error::InvalidSecretKey)?;
    let bytes = sk.to_bytes();
    Self::from_bytes(&bytes)
  }

  /// Parse from 32-byte big-endian scalar.
  #[expect(unsafe_code, reason = "blst C FFI")]
  pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self, Error> {
    let mut scalar = blst_scalar::default();
    unsafe { blst_scalar_from_bendian(&mut scalar, bytes.as_ptr()) };
    if unsafe { blst_sk_check(&scalar) } {
      Ok(Self(scalar))
    } else {
      Err(Error::InvalidSecretKey)
    }
  }

  /// Serialize to 32 bytes.
  #[expect(unsafe_code, reason = "blst C FFI")]
  pub fn to_bytes(&self) -> [u8; 32] {
    let mut out = [0u8; 32];
    unsafe { blst_bendian_from_scalar(out.as_mut_ptr(), &self.0) };
    out
  }

  /// Derive the corresponding public key (G1 point).
  #[expect(unsafe_code, reason = "blst C FFI")]
  pub fn public_key(&self) -> PublicKey {
    let mut pk = blst_p1::default();
    unsafe { blst_sk_to_pk_in_g1(&mut pk, &self.0) };
    let mut aff = blst_p1_affine::default();
    unsafe { blst_p1_to_affine(&mut aff, &pk) };
    PublicKey::from_inner(aff)
  }

  /// Sign a 32-byte message hash using the legacy scheme (no DST, Shallue–van
  /// de Woestijne hash-to-G2).
  #[expect(unsafe_code, reason = "blst C FFI")]
  pub fn sign(&self, msg: &[u8; 32]) -> Signature {
    let h = hash::hash_to_g2(msg);
    // blst_sign_pk_in_g1 applies IETF transformations, do manually instead.
    let mut sig = blst_p2::default();
    unsafe { blst_p2_mult(&mut sig, &h, self.0.b.as_ptr(), 255) };
    let mut aff = blst_p2_affine::default();
    unsafe { blst_p2_to_affine(&mut aff, &sig) };
    Signature::from_inner(aff)
  }
}

impl Drop for SecretKey {
  fn drop(&mut self) {
    self.0.b.zeroize();
  }
}

impl fmt::Debug for SecretKey {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "SecretKey(..)")
  }
}
