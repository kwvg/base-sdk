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
use crate::bls::blst_ffi;

use zeroize::Zeroize;

use core::fmt;

/// A legacy BLS secret key (32-byte scalar).
#[derive(Clone)]
pub struct SecretKey(blst::blst_scalar);

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
  pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self, Error> {
    let scalar = blst_ffi::scalar_from_bendian(bytes);
    if blst_ffi::sk_check(&scalar) {
      Ok(Self(scalar))
    } else {
      Err(Error::InvalidSecretKey)
    }
  }

  /// Serialize to 32 bytes.
  pub fn to_bytes(&self) -> [u8; 32] {
    blst_ffi::bendian_from_scalar(&self.0)
  }

  /// Derive the corresponding public key (G1 point).
  pub fn public_key(&self) -> PublicKey {
    PublicKey::from_inner(blst_ffi::sk_to_pk2_in_g1(&self.0))
  }

  /// Sign a 32-byte message hash using the legacy scheme (no DST, Shallue-van
  /// de Woestijne hash-to-G2).
  pub fn sign(&self, msg: &[u8; 32]) -> Signature {
    let h = hash::hash_to_g2(msg);
    // blst_sign_pk_in_g1 applies IETF transformations, do manually instead.
    let sig = blst_ffi::p2_mult(&h, &self.0.b, blst_ffi::FR_BITS);
    let aff = blst_ffi::p2_to_affine(&sig);
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
