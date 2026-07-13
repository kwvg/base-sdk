//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! IETF BLS signature (96-byte compressed G2 point).

use super::pk::PublicKey;
use crate::bls::scheme_ops::BlsScheme;
use crate::bls::BlsError;
use crate::bls::{BlsScIetf, BlsSigId};

use blst::min_pk;

/// A BLS signature (96-byte compressed G2 point).
#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
#[cfg_attr(
  feature = "serde",
  serde(into = "crate::BlsSignatureBytes", try_from = "crate::BlsSignatureBytes",)
)]
pub struct Signature(pub(super) min_pk::Signature);

impl Signature {
  pub(super) fn from_inner(inner: min_pk::Signature) -> Self {
    Self(inner)
  }

  /// Deserialize from 96 compressed bytes.
  pub fn from_bytes(bytes: &[u8; 96]) -> Result<Self, BlsError> {
    BlsScIetf::sig_from_bytes(bytes).map(Self).map_err(Into::into)
  }

  /// Serialize to 96 compressed bytes.
  pub fn to_bytes(&self) -> [u8; 96] {
    BlsScIetf::sig_to_bytes(&self.0)
  }

  /// Verify with the Basic scheme.
  pub fn verify(&self, msg: &[u8], pk: &PublicKey) -> Result<(), BlsError> {
    BlsScIetf::verify(&self.0, msg, &pk.0).map_err(Into::into)
  }

  /// Verify with a specific scheme.
  pub fn verify_with(&self, msg: &[u8], pk: &PublicKey, scheme: BlsSigId) -> Result<(), BlsError> {
    BlsScIetf::verify_with(&self.0, msg, &pk.0, scheme).map_err(Into::into)
  }
}

crate::common::bls::impl_hash_via_bytes!(Signature);

impl From<Signature> for crate::BlsSignatureBytes {
  fn from(sig: Signature) -> Self {
    Self(sig.to_bytes())
  }
}

impl TryFrom<crate::BlsSignatureBytes> for Signature {
  type Error = crate::bls::BlsError;

  fn try_from(bytes: crate::BlsSignatureBytes) -> Result<Self, Self::Error> {
    Self::from_bytes(&bytes.0)
  }
}
