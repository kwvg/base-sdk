//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Legacy BLS signatures (non-standard hash-to-G2, min-pubkey-size).

mod agg;
mod sig;

pub mod threshold;

pub use crate::bls::BlsError;
pub use agg::{
  aggregate_pk, aggregate_sig, aggregate_sk, fast_verify_aggregates, secure_verify_aggregates, verify_aggregates,
};
pub use sig::Signature;

use crate::bls::scheme_ops::BlsScheme;

pub type SecretKey = crate::bls::BlsSecretKey<crate::bls::BlsScChia>;
pub type PublicKey = crate::bls::BlsPublicKey<crate::bls::BlsScChia>;

impl SecretKey {
  /// Sign a 32-byte message hash using the legacy scheme (no DST, Shallue-van
  /// de Woestijne hash-to-G2).
  pub fn sign(&self, msg: &[u8; 32]) -> Signature {
    Signature::from_inner(crate::bls::BlsScChia::sign(&self.0, msg))
  }
}

// Compile-time contract: must match bls_ietf's shared API surface.
const _: () = {
  use crate::common::bls::contract::*;
  impl BlsSecretKey for SecretKey {
    type Error = BlsError;
    type PublicKey = PublicKey;
    type Signature = Signature;
    type Msg = [u8; 32];
    fn generate(ikm: &[u8]) -> Result<Self, BlsError> {
      SecretKey::generate(ikm)
    }
    fn from_bytes(b: &[u8; 32]) -> Result<Self, BlsError> {
      SecretKey::from_bytes(b)
    }
    fn to_bytes(&self) -> [u8; 32] {
      self.to_bytes()
    }
    fn public_key(&self) -> PublicKey {
      self.public_key()
    }
    fn sign(&self, msg: &[u8; 32]) -> Signature {
      self.sign(msg)
    }
  }
  impl BlsSignature for Signature {
    type Error = BlsError;
    type PublicKey = PublicKey;
    type Msg = [u8; 32];
    fn from_bytes(b: &[u8; 96]) -> Result<Self, BlsError> {
      Signature::from_bytes(b)
    }
    fn to_bytes(&self) -> [u8; 96] {
      self.to_bytes()
    }
    fn verify(&self, msg: &[u8; 32], pk: &PublicKey) -> Result<(), BlsError> {
      self.verify(msg, pk)
    }
  }
};
