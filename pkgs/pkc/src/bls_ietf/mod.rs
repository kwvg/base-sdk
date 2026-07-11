//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! IETF BLS12-381 signatures (basic scheme, min-pubkey-size).

mod agg;
mod sig;

pub mod threshold;

pub use crate::bls::BlsError;
pub use agg::{
  aggregate_pk, aggregate_sig, aggregate_sk, fast_verify_aggregates, secure_verify_aggregates, verify_aggregates,
};
pub use sig::Signature;

use crate::bls::scheme_ops::BlsScheme;
use crate::bls::BlsSigId;

pub type SecretKey = crate::bls::BlsSecretKey<crate::bls::BlsScIetf>;
pub type PublicKey = crate::bls::BlsPublicKey<crate::bls::BlsScIetf>;

impl SecretKey {
  /// Sign with the Basic scheme.
  pub fn sign(&self, msg: &[u8]) -> Signature {
    Signature::from_inner(crate::bls::BlsScIetf::sign(&self.0, msg))
  }

  /// Sign with a specific scheme.
  pub fn sign_with(&self, msg: &[u8], scheme: BlsSigId) -> Signature {
    Signature::from_inner(crate::bls::BlsScIetf::sign_with(&self.0, msg, scheme).expect("IETF supports both schemes"))
  }

  /// Produce a proof of possession by signing the serialized public key with
  /// the PoP DST.
  pub fn prove_possession(&self) -> Signature {
    let pk = crate::bls::BlsScIetf::derive_pk(&self.0);
    Signature::from_inner(
      crate::bls::BlsScIetf::prove_possession(&self.0, &pk).expect("IETF supports proofs of possession"),
    )
  }
}

impl PublicKey {
  /// Verify a proof of possession against this key.
  pub fn verify_possession(&self, pop: &Signature) -> Result<(), BlsError> {
    crate::bls::BlsScIetf::verify_possession(&self.0, &pop.0).map_err(Into::into)
  }
}

// Compile-time contract: if any of these methods are
// removed or their signatures change, this block fails.
const _: () = {
  use crate::common::bls::contract::*;
  impl BlsSecretKey for SecretKey {
    type Error = BlsError;
    type PublicKey = PublicKey;
    type Signature = Signature;
    type Msg = [u8];
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
    fn sign(&self, msg: &[u8]) -> Signature {
      self.sign(msg)
    }
  }
  impl BlsSignature for Signature {
    type Error = BlsError;
    type PublicKey = PublicKey;
    type Msg = [u8];
    fn from_bytes(b: &[u8; 96]) -> Result<Self, BlsError> {
      Signature::from_bytes(b)
    }
    fn to_bytes(&self) -> [u8; 96] {
      self.to_bytes()
    }
    fn verify(&self, msg: &[u8], pk: &PublicKey) -> Result<(), BlsError> {
      self.verify(msg, pk)
    }
  }
};
