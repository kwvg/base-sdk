//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Legacy BLS public key (48-byte G1 point, legacy serialization).

use super::error::Error;
use super::ser;
use super::sk::SecretKey;

use blst::blst_p1_affine;

/// A legacy BLS public key (48-byte G1 point in legacy serialization).
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(
  feature = "serde",
  serde(into = "dash_types::BlsPublicKeyBytes", try_from = "dash_types::BlsPublicKeyBytes",)
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
  #[expect(unsafe_code, reason = "blst C FFI")]
  pub fn dh_exchange(sk: &SecretKey, peer_pk: &PublicKey) -> Result<Self, Error> {
    use blst::*;
    use zeroize::Zeroize;
    let mut pk_proj = blst_p1::default();
    unsafe { blst_p1_from_affine(&mut pk_proj, &peer_pk.0) };
    let mut sk_bytes = sk.to_bytes();
    let mut sk_scalar = blst_scalar::default();
    unsafe { blst_scalar_from_bendian(&mut sk_scalar, sk_bytes.as_ptr()) };
    let mut out = blst_p1::default();
    unsafe { blst_p1_mult(&mut out, &pk_proj, sk_scalar.b.as_ptr(), 255) };
    let mut out_aff = blst_p1_affine::default();
    unsafe { blst_p1_to_affine(&mut out_aff, &out) };
    sk_bytes.zeroize();
    sk_scalar.b.zeroize();
    Ok(Self(out_aff))
  }
}

crate::common::bls::impl_hash_via_bytes!(PublicKey);

impl From<PublicKey> for dash_types::BlsPublicKeyBytes {
  fn from(pk: PublicKey) -> Self {
    Self(pk.to_bytes())
  }
}

impl TryFrom<dash_types::BlsPublicKeyBytes> for PublicKey {
  type Error = super::error::Error;

  fn try_from(bytes: dash_types::BlsPublicKeyBytes) -> Result<Self, Self::Error> {
    Self::from_bytes(&bytes.0)
  }
}
