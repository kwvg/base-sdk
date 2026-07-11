//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! IETF BLS public key (48-byte compressed G1 point).

use super::sig::Signature;
use super::sk::SecretKey;
use crate::bls::scheme_ops::BlsScheme;
use crate::bls::BlsError;
use crate::bls::BlsScIetf;

use blst::min_pk;

/// A BLS public key (48-byte compressed G1 point).
#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
#[cfg_attr(
  feature = "serde",
  serde(
    into = "crate::bls::BlsPkBytes<crate::bls::BlsScIetf>",
    try_from = "crate::bls::BlsPkBytes<crate::bls::BlsScIetf>",
  )
)]
pub struct PublicKey(pub(super) min_pk::PublicKey);

impl PublicKey {
  pub(super) fn from_inner(inner: min_pk::PublicKey) -> Self {
    Self(inner)
  }

  /// Deserialize from 48 compressed bytes.
  pub fn from_bytes(bytes: &[u8; 48]) -> Result<Self, BlsError> {
    BlsScIetf::pk_from_bytes(bytes).map(Self).map_err(Into::into)
  }

  /// Serialize to 48 compressed bytes.
  pub fn to_bytes(&self) -> [u8; 48] {
    BlsScIetf::pk_to_bytes(&self.0)
  }

  /// Compute a DH shared key: `sk * peer_pk`.
  pub fn dh_exchange(sk: &SecretKey, peer_pk: &PublicKey) -> Result<Self, BlsError> {
    BlsScIetf::dh_exchange(&sk.0, &peer_pk.0).map(Self).map_err(Into::into)
  }

  /// Verify a proof of possession against this key.
  pub fn verify_possession(&self, pop: &Signature) -> Result<(), BlsError> {
    BlsScIetf::verify_possession(&self.0, &pop.0).map_err(Into::into)
  }
}

crate::common::bls::impl_hash_via_bytes!(PublicKey);

impl From<PublicKey> for crate::bls::BlsPkBytes<crate::bls::BlsScIetf> {
  fn from(pk: PublicKey) -> Self {
    Self::from_bytes(pk.to_bytes())
  }
}

impl TryFrom<crate::bls::BlsPkBytes<crate::bls::BlsScIetf>> for PublicKey {
  type Error = crate::bls::BlsError;

  fn try_from(bytes: crate::bls::BlsPkBytes<crate::bls::BlsScIetf>) -> Result<Self, Self::Error> {
    Self::from_bytes(bytes.as_bytes())
  }
}
