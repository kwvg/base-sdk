//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Legacy BLS public key (48-byte G1 point, legacy serialization).

use super::error::Error;
use super::ser;
use super::sk::SecretKey;
use crate::bls::blst_ffi;

use blst::blst_p1_affine;

/// A legacy BLS public key (48-byte G1 point in legacy serialization).
#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
#[cfg_attr(
  feature = "serde",
  serde(into = "crate::BlsPublicKeyBytes", try_from = "crate::BlsPublicKeyBytes",)
)]
pub struct PublicKey(pub(super) blst_p1_affine);

impl PublicKey {
  pub(super) fn from_inner(inner: blst_p1_affine) -> Self {
    Self(inner)
  }

  /// Deserialize from 48 legacy-format bytes.
  pub fn from_bytes(bytes: &[u8; 48]) -> Result<Self, Error> {
    ser::deser_g1(bytes).map(Self)
  }

  /// Serialize to 48 legacy-format bytes.
  pub fn to_bytes(&self) -> [u8; 48] {
    ser::ser_g1(&self.0)
  }

  /// Compute a DH shared key: `sk * peer_pk`.
  pub fn dh_exchange(sk: &SecretKey, peer_pk: &PublicKey) -> Result<Self, Error> {
    use zeroize::Zeroize;
    let mut sk_bytes = sk.to_bytes();
    let mut sk_scalar = blst_ffi::scalar_from_bendian(&sk_bytes);
    let out_aff = blst_ffi::p1_mult(&peer_pk.0, &sk_scalar.b, blst_ffi::FR_BITS);
    sk_bytes.zeroize();
    sk_scalar.b.zeroize();
    Ok(Self(out_aff))
  }
}

crate::common::bls::impl_hash_via_bytes!(PublicKey);

impl From<PublicKey> for crate::BlsPublicKeyBytes {
  fn from(pk: PublicKey) -> Self {
    Self(pk.to_bytes())
  }
}

impl TryFrom<crate::BlsPublicKeyBytes> for PublicKey {
  type Error = super::error::Error;

  fn try_from(bytes: crate::BlsPublicKeyBytes) -> Result<Self, Self::Error> {
    Self::from_bytes(&bytes.0)
  }
}
