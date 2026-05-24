//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! IETF BLS public key (48-byte compressed G1 point).

use super::error::Error;
use super::sig::Signature;
use super::sk::SecretKey;
use super::DST_POP_PROVE;

use blst::min_pk;
use blst::BLST_ERROR;

/// A BLS public key (48-byte compressed G1 point).
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(
  feature = "serde",
  serde(into = "dash_types::BlsPublicKeyBytes", try_from = "dash_types::BlsPublicKeyBytes",)
)]
pub struct PublicKey(pub(super) min_pk::PublicKey);

impl PublicKey {
  pub(super) fn from_inner(inner: min_pk::PublicKey) -> Self {
    Self(inner)
  }

  /// Deserialize from 48 compressed bytes.
  pub fn from_bytes(bytes: &[u8; 48]) -> Result<Self, Error> {
    min_pk::PublicKey::from_bytes(bytes)
      .map(Self)
      .map_err(|_| Error::InvalidPublicKey)
  }

  /// Serialize to 48 compressed bytes.
  pub fn to_bytes(&self) -> [u8; 48] {
    self.0.compress()
  }

  /// Compute a DH shared key: `sk * peer_pk`.
  #[expect(unsafe_code, reason = "blst C FFI")]
  pub fn dh_exchange(sk: &SecretKey, peer_pk: &PublicKey) -> Result<Self, Error> {
    use blst::*;
    use zeroize::Zeroize;
    let compressed = peer_pk.0.compress();
    let mut aff = blst_p1_affine::default();
    let rc = unsafe { blst_p1_uncompress(&mut aff, compressed.as_ptr()) };
    if rc != BLST_ERROR::BLST_SUCCESS {
      return Err(Error::InvalidPublicKey);
    }
    let mut proj = blst_p1::default();
    unsafe { blst_p1_from_affine(&mut proj, &aff) };
    let mut sk_bytes = sk.to_bytes();
    let mut sk_scalar = blst_scalar::default();
    unsafe { blst_scalar_from_bendian(&mut sk_scalar, sk_bytes.as_ptr()) };
    let mut out = blst_p1::default();
    unsafe { blst_p1_mult(&mut out, &proj, sk_scalar.b.as_ptr(), 255) };
    let mut out_aff = blst_p1_affine::default();
    unsafe { blst_p1_to_affine(&mut out_aff, &out) };
    let mut out_bytes = [0u8; 48];
    unsafe { blst_p1_affine_compress(out_bytes.as_mut_ptr(), &out_aff) };
    sk_bytes.zeroize();
    sk_scalar.b.zeroize();
    Self::from_bytes(&out_bytes)
  }

  /// Verify a proof of possession against this key.
  pub fn verify_possession(&self, pop: &Signature) -> Result<(), Error> {
    let pk_bytes = self.to_bytes();
    let result = pop.0.verify(true, &pk_bytes, DST_POP_PROVE, &[], &self.0, true);
    if result == BLST_ERROR::BLST_SUCCESS {
      Ok(())
    } else {
      Err(Error::VerifyFailed)
    }
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
