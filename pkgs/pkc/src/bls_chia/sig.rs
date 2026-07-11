//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Legacy BLS signature (96-byte G2 point, legacy serialization).

use super::PublicKey;
use crate::bls::scheme_ops::BlsScheme;
use crate::bls::BlsError;
use crate::bls::BlsScChia;

use blst::blst_p2_affine;

/// A legacy BLS signature (96-byte G2 point in legacy serialization).
#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
#[cfg_attr(
  feature = "serde",
  serde(
    into = "crate::bls::BlsSigBytes<crate::bls::BlsScChia>",
    try_from = "crate::bls::BlsSigBytes<crate::bls::BlsScChia>",
  )
)]
pub struct Signature(pub(super) blst_p2_affine);

impl Signature {
  pub(super) fn from_inner(inner: blst_p2_affine) -> Self {
    Self(inner)
  }

  /// Deserialize from 96 legacy-format bytes.
  pub fn from_bytes(bytes: &[u8; 96]) -> Result<Self, BlsError> {
    BlsScChia::sig_from_bytes(bytes).map(Self).map_err(Into::into)
  }

  /// Serialize to 96 legacy-format bytes.
  pub fn to_bytes(&self) -> [u8; 96] {
    BlsScChia::sig_to_bytes(&self.0)
  }

  /// Verify against a 32-byte message and public key via pairing check:
  /// e(sig, G1) == e(H(msg), pk).
  pub fn verify(&self, msg: &[u8; 32], pk: &PublicKey) -> Result<(), BlsError> {
    BlsScChia::verify(&self.0, msg, &pk.0).map_err(Into::into)
  }
}

crate::common::bls::impl_hash_via_bytes!(Signature);

impl From<Signature> for crate::bls::BlsSigBytes<crate::bls::BlsScChia> {
  fn from(sig: Signature) -> Self {
    Self::from_bytes(sig.to_bytes())
  }
}

impl TryFrom<crate::bls::BlsSigBytes<crate::bls::BlsScChia>> for Signature {
  type Error = crate::bls::BlsError;

  fn try_from(bytes: crate::bls::BlsSigBytes<crate::bls::BlsScChia>) -> Result<Self, Self::Error> {
    Self::from_bytes(bytes.as_bytes())
  }
}
