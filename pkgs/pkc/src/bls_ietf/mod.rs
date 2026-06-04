//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! IETF BLS12-381 signatures (basic scheme, min-pubkey-size).

mod agg;
mod error;
mod pk;
mod sig;
mod sk;

pub mod threshold;

pub use agg::{
  aggregate_pk, aggregate_sig, aggregate_sk, fast_verify_aggregates, secure_verify_aggregates, verify_aggregates,
};
pub use error::Error;
pub use pk::PublicKey;
pub use sig::Signature;
pub use sk::{Scheme, SecretKey};

const DST_BASIC: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";
const DST_POP: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";
const DST_POP_PROVE: &[u8] = b"BLS_POP_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";

const DST: &[u8] = DST_BASIC;

// Compile-time contract: if any of these methods are
// removed or their signatures change, this block fails.
const _: () = {
  use crate::common::bls::contract::*;
  impl BlsSecretKey for SecretKey {
    type Error = Error;
    type PublicKey = PublicKey;
    type Signature = Signature;
    type Msg = [u8];
    fn generate(ikm: &[u8]) -> Result<Self, Error> {
      SecretKey::generate(ikm)
    }
    fn from_bytes(b: &[u8; 32]) -> Result<Self, Error> {
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
    type Error = Error;
    type SecretKey = SecretKey;
    fn from_bytes(b: &[u8; 48]) -> Result<Self, Error> {
      PublicKey::from_bytes(b)
    }
    fn to_bytes(&self) -> [u8; 48] {
      self.to_bytes()
    }
    fn dh_exchange(sk: &SecretKey, pk: &Self) -> Result<Self, Error> {
      PublicKey::dh_exchange(sk, pk)
    }
  }
  impl BlsSignature for Signature {
    type Error = Error;
    type PublicKey = PublicKey;
    type Msg = [u8];
    fn from_bytes(b: &[u8; 96]) -> Result<Self, Error> {
      Signature::from_bytes(b)
    }
    fn to_bytes(&self) -> [u8; 96] {
      self.to_bytes()
    }
    fn verify(&self, msg: &[u8], pk: &PublicKey) -> Result<(), Error> {
      self.verify(msg, pk)
    }
  }
};
