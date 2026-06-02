//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! IETF BLS signature (96-byte compressed G2 point).

use super::error::Error;
use super::pk::PublicKey;
use super::sk::Scheme;
use super::{DST, DST_POP};

use blst::min_pk;
use blst::BLST_ERROR;

/// A BLS signature (96-byte compressed G2 point).
#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(
  feature = "serde",
  serde(into = "dash_types::BlsSignatureBytes", try_from = "dash_types::BlsSignatureBytes",)
)]
pub struct Signature(pub(super) min_pk::Signature);

impl Signature {
  pub(super) fn from_inner(inner: min_pk::Signature) -> Self {
    Self(inner)
  }

  /// Deserialize from 96 compressed bytes.
  pub fn from_bytes(bytes: &[u8; 96]) -> Result<Self, Error> {
    min_pk::Signature::from_bytes(bytes)
      .map(Self)
      .map_err(|_| Error::InvalidSignature)
  }

  /// Serialize to 96 compressed bytes.
  pub fn to_bytes(&self) -> [u8; 96] {
    self.0.compress()
  }

  /// Verify with the Basic scheme.
  pub fn verify(&self, msg: &[u8], pk: &PublicKey) -> Result<(), Error> {
    self.verify_raw(msg, pk, DST)
  }

  /// Verify with a specific scheme.
  pub fn verify_with(&self, msg: &[u8], pk: &PublicKey, scheme: Scheme) -> Result<(), Error> {
    let dst = match scheme {
      Scheme::Basic => DST,
      Scheme::ProofOfPossession => DST_POP,
    };
    self.verify_raw(msg, pk, dst)
  }

  fn verify_raw(&self, msg: &[u8], pk: &PublicKey, dst: &[u8]) -> Result<(), Error> {
    let result = self.0.verify(true, msg, dst, &[], &pk.0, true);
    if result == BLST_ERROR::BLST_SUCCESS {
      Ok(())
    } else {
      Err(Error::VerifyFailed)
    }
  }
}

crate::common::bls::impl_hash_via_bytes!(Signature);

impl From<Signature> for dash_types::BlsSignatureBytes {
  fn from(sig: Signature) -> Self {
    Self(sig.to_bytes())
  }
}

impl TryFrom<dash_types::BlsSignatureBytes> for Signature {
  type Error = super::error::Error;

  fn try_from(bytes: dash_types::BlsSignatureBytes) -> Result<Self, Self::Error> {
    Self::from_bytes(&bytes.0)
  }
}
