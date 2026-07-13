//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Legacy BLS signature (96-byte G2 point, legacy serialization).

use super::error::Error;
use super::hash;
use super::pk::PublicKey;
use super::ser;
use crate::bls::blst_ffi;

use blst::blst_p2_affine;

/// A legacy BLS signature (96-byte G2 point in legacy serialization).
#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
#[cfg_attr(
  feature = "serde",
  serde(into = "crate::BlsSignatureBytes", try_from = "crate::BlsSignatureBytes",)
)]
pub struct Signature(pub(super) blst_p2_affine);

impl Signature {
  pub(super) fn from_inner(inner: blst_p2_affine) -> Self {
    Self(inner)
  }

  /// Deserialize from 96 legacy-format bytes.
  pub fn from_bytes(bytes: &[u8; 96]) -> Result<Self, Error> {
    ser::deser_g2(bytes).map(Self)
  }

  /// Serialize to 96 legacy-format bytes.
  pub fn to_bytes(&self) -> [u8; 96] {
    ser::ser_g2(&self.0)
  }

  /// Verify against a 32-byte message and public key via pairing check:
  /// e(sig, G1) == e(H(msg), pk).
  pub fn verify(&self, msg: &[u8; 32], pk: &PublicKey) -> Result<(), Error> {
    let h_proj = hash::hash_to_g2(msg);
    let valid = blst_ffi::pairings_equal_with_g1_generator(&self.0, &h_proj, &pk.0);
    if valid {
      Ok(())
    } else {
      Err(Error::VerifyFailed)
    }
  }
}

crate::common::bls::impl_hash_via_bytes!(Signature);

impl From<Signature> for crate::BlsSignatureBytes {
  fn from(sig: Signature) -> Self {
    Self(sig.to_bytes())
  }
}

impl TryFrom<crate::BlsSignatureBytes> for Signature {
  type Error = super::error::Error;

  fn try_from(bytes: crate::BlsSignatureBytes) -> Result<Self, Self::Error> {
    Self::from_bytes(&bytes.0)
  }
}
