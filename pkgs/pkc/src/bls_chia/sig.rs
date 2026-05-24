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

use blst::*;

/// A legacy BLS signature (96-byte G2 point in legacy serialization).
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(
  feature = "serde",
  serde(into = "dash_types::BlsSignatureBytes", try_from = "dash_types::BlsSignatureBytes",)
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
  #[expect(unsafe_code, reason = "blst C FFI")]
  pub fn verify(&self, msg: &[u8; 32], pk: &PublicKey) -> Result<(), Error> {
    let h_proj = hash::hash_to_g2(msg);
    let mut h_aff = blst_p2_affine::default();
    unsafe { blst_p2_to_affine(&mut h_aff, &h_proj) };

    let g1 = unsafe { *blst_p1_generator() };
    let mut gen_aff = blst_p1_affine::default();
    unsafe { blst_p1_to_affine(&mut gen_aff, &g1) };

    // e(sig, G1)
    let mut ml1 = blst_fp12::default();
    unsafe { blst_miller_loop(&mut ml1, &self.0, &gen_aff) };

    // e(H(msg), pk)
    let mut ml2 = blst_fp12::default();
    unsafe { blst_miller_loop(&mut ml2, &h_aff, &pk.0) };

    // e(sig, G1) == e(H(msg), pk)
    let valid = unsafe { blst_fp12_finalverify(&ml1, &ml2) };
    if valid {
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

extern "C" {
  fn blst_p1_generator() -> *const blst_p1;
}
