//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! IETF BLS12-381 signatures (basic scheme, min-pubkey-size).

mod agg;
mod sig;
mod sk;

pub mod threshold;

pub use crate::bls::BlsError;
pub use agg::{
  aggregate_pk, aggregate_sig, aggregate_sk, fast_verify_aggregates, secure_verify_aggregates, verify_aggregates,
};
pub use sig::Signature;
pub use sk::SecretKey;

use crate::bls::scheme_ops::BlsScheme;

pub type PublicKey = crate::bls::BlsPublicKey<crate::bls::BlsScIetf>;

impl PublicKey {
  /// Compute a DH shared key: `sk * peer_pk`.
  pub fn dh_exchange(sk: &SecretKey, peer_pk: &PublicKey) -> Result<Self, BlsError> {
    crate::bls::BlsScIetf::dh_exchange(&sk.0, &peer_pk.0)
      .map(Self::from_inner)
      .map_err(Into::into)
  }

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
  impl BlsPublicKey for PublicKey {
    type Error = BlsError;
    type SecretKey = SecretKey;
    fn from_bytes(b: &[u8; 48]) -> Result<Self, BlsError> {
      PublicKey::from_bytes(b)
    }
    fn to_bytes(&self) -> [u8; 48] {
      self.to_bytes()
    }
    fn dh_exchange(sk: &SecretKey, pk: &Self) -> Result<Self, BlsError> {
      PublicKey::dh_exchange(sk, pk)
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
