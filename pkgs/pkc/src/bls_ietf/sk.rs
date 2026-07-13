//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! IETF BLS secret key.

use super::sig::Signature;
use super::PublicKey;
use crate::bls::scheme_ops::BlsScheme;
use crate::bls::BlsError;
use crate::bls::{BlsScIetf, BlsSigId};

use blst::min_pk;

use core::fmt;

/// A BLS secret key (32-byte scalar).
///
/// Zeroised on drop by the blst crate.
#[derive(Clone)]
pub struct SecretKey(pub(super) min_pk::SecretKey);

impl SecretKey {
  /// Derive a secret key from input keying material.
  ///
  /// # Errors
  ///
  /// Returns `InvalidKeyMaterial` when `ikm` is shorter than 32 bytes.
  pub fn generate(ikm: &[u8]) -> Result<Self, BlsError> {
    BlsScIetf::generate(ikm).map(Self).map_err(Into::into)
  }

  /// Parse from a 32-byte big-endian scalar.
  pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self, BlsError> {
    BlsScIetf::sk_from_bytes(bytes).map(Self).map_err(Into::into)
  }

  /// Serialize to 32 bytes.
  pub fn to_bytes(&self) -> [u8; 32] {
    BlsScIetf::sk_to_bytes(&self.0)
  }

  /// Derive the corresponding public key.
  pub fn public_key(&self) -> PublicKey {
    PublicKey::from_inner(BlsScIetf::derive_pk(&self.0))
  }

  /// Sign with the Basic scheme.
  pub fn sign(&self, msg: &[u8]) -> Signature {
    Signature::from_inner(BlsScIetf::sign(&self.0, msg))
  }

  /// Sign with a specific scheme.
  pub fn sign_with(&self, msg: &[u8], scheme: BlsSigId) -> Signature {
    Signature::from_inner(BlsScIetf::sign_with(&self.0, msg, scheme).expect("IETF supports both schemes"))
  }

  /// Produce a proof of possession by signing the serialized public key with
  /// the PoP DST.
  pub fn prove_possession(&self) -> Signature {
    let pk = BlsScIetf::derive_pk(&self.0);
    Signature::from_inner(BlsScIetf::prove_possession(&self.0, &pk).expect("IETF supports proofs of possession"))
  }
}

impl fmt::Debug for SecretKey {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "SecretKey(..)")
  }
}
