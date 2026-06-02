//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! IETF BLS secret key.

use super::error::Error;
use super::pk::PublicKey;
use super::sig::Signature;
use super::{DST, DST_POP, DST_POP_PROVE};

use blst::min_pk;

use core::fmt;

/// BLS signature scheme (determines the DST).
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Scheme {
  /// Basic scheme (NUL augmentation).
  Basic,
  /// Proof of Possession scheme.
  ProofOfPossession,
}

/// A BLS secret key (32-byte scalar).
///
/// Zeroised on drop by the blst crate.
#[derive(Clone)]
pub struct SecretKey(min_pk::SecretKey);

impl SecretKey {
  /// Derive a secret key from input keying material.
  ///
  /// # Errors
  ///
  /// Returns `InvalidKeyMaterial` when `ikm` is shorter than 32 bytes.
  pub fn generate(ikm: &[u8]) -> Result<Self, Error> {
    min_pk::SecretKey::key_gen(ikm, &[])
      .map(Self)
      .map_err(|_| Error::InvalidKeyMaterial)
  }

  /// Parse from a 32-byte big-endian scalar.
  pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self, Error> {
    min_pk::SecretKey::from_bytes(bytes)
      .map(Self)
      .map_err(|_| Error::InvalidSecretKey)
  }

  /// Serialize to 32 bytes.
  pub fn to_bytes(&self) -> [u8; 32] {
    self.0.to_bytes()
  }

  /// Derive the corresponding public key.
  pub fn public_key(&self) -> PublicKey {
    PublicKey::from_inner(self.0.sk_to_pk())
  }

  /// Sign with the Basic scheme.
  pub fn sign(&self, msg: &[u8]) -> Signature {
    Signature::from_inner(self.0.sign(msg, DST, &[]))
  }

  /// Sign with a specific scheme.
  pub fn sign_with(&self, msg: &[u8], scheme: Scheme) -> Signature {
    let dst = match scheme {
      Scheme::Basic => DST,
      Scheme::ProofOfPossession => DST_POP,
    };
    Signature::from_inner(self.0.sign(msg, dst, &[]))
  }

  /// Produce a proof of possession by signing the serialized public key with
  /// the PoP DST.
  pub fn prove_possession(&self) -> Signature {
    let pk_bytes = self.public_key().to_bytes();
    Signature::from_inner(self.0.sign(&pk_bytes, DST_POP_PROVE, &[]))
  }
}

impl fmt::Debug for SecretKey {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "SecretKey(..)")
  }
}
