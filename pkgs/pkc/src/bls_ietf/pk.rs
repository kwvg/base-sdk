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
use crate::bls::blst_ffi;

use blst::min_pk;
use blst::BLST_ERROR;

/// A BLS public key (48-byte compressed G1 point).
#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
#[cfg_attr(
  feature = "serde",
  serde(into = "crate::BlsPublicKeyBytes", try_from = "crate::BlsPublicKeyBytes",)
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
  pub fn dh_exchange(sk: &SecretKey, peer_pk: &PublicKey) -> Result<Self, Error> {
    use zeroize::Zeroize;
    let compressed = peer_pk.0.compress();
    let aff = blst_ffi::p1_uncompress(&compressed).map_err(|_| Error::InvalidPublicKey)?;
    let mut sk_bytes = sk.to_bytes();
    let mut sk_scalar = blst_ffi::scalar_from_bendian(&sk_bytes);
    let out_aff = blst_ffi::p1_mult(&aff, &sk_scalar.b, blst_ffi::FR_BITS);
    let out_bytes = blst_ffi::p1_affine_compress(&out_aff);
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
