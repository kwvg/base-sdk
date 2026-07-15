//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Precomputed hash-to-G2 message points for repeated verification.

use crate::bls::error::BlsError;
use crate::bls::public_ops::BlsPublicKey;
use crate::bls::scheme_ops::BlsScheme;
use crate::bls::schemes::BlsSchemeId;
use crate::bls::sig_basic::BlsSignature;
use crate::prelude::*;

use blst::blst_p2_affine;

use core::fmt::{Debug, Formatter, Result as FmtResult};
use core::marker::PhantomData;

/// A message hashed onto G2 under scheme `S`'s hash-to-curve.
///
/// Hashing dominates single-signature verification; callers that
/// verify many signatures over the same message can hash once and
/// use [`BlsSignature::verify_prehashed`].
pub struct BlsMessagePoint<S: BlsSchemeId> {
  pub(crate) point: blst_p2_affine,
  _pd: PhantomData<S>,
}

impl<S: BlsSchemeId + BlsScheme> BlsMessagePoint<S> {
  /// Hash a message onto G2.
  ///
  /// # Errors
  ///
  /// Returns `InvalidMessageLength` for Chia when `msg` is not
  /// exactly 32 bytes.
  pub fn hash(msg: &[u8]) -> Result<Self, BlsError> {
    Ok(Self {
      point: S::hash_to_g2_point(msg)?,
      _pd: PhantomData,
    })
  }
}

impl<S: BlsSchemeId> Clone for BlsMessagePoint<S> {
  fn clone(&self) -> Self {
    Self {
      point: self.point,
      _pd: PhantomData,
    }
  }
}

impl<S: BlsSchemeId> PartialEq for BlsMessagePoint<S> {
  fn eq(&self, other: &Self) -> bool {
    self.point == other.point
  }
}

impl<S: BlsSchemeId> Eq for BlsMessagePoint<S> {}

impl<S: BlsSchemeId> Debug for BlsMessagePoint<S> {
  fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
    write!(f, "BlsMessagePoint<{}>(..)", S::LABEL)
  }
}

impl<S: BlsSchemeId + BlsScheme> BlsSignature<S> {
  /// Verify against a precomputed message point; equivalent to
  /// [`Self::verify`] with the message that produced `msg_point`.
  ///
  /// # Errors
  ///
  /// Returns `VerifyFailed` when the pairing check fails.
  pub fn verify_prehashed(&self, msg_point: &BlsMessagePoint<S>, pk: &BlsPublicKey<S>) -> Result<(), BlsError> {
    S::verify_prehashed(&self.0, &msg_point.point, &pk.0)
  }

  /// Verify an aggregate over per-signer precomputed message
  /// points; equivalent to [`Self::verify_aggregates`] with the
  /// messages that produced `msg_points`.
  ///
  /// # Errors
  ///
  /// As [`Self::verify_aggregates`]; the basic scheme's distinct
  /// message rule is enforced on the hash points.
  pub fn verify_aggregates_prehashed(
    &self,
    msg_points: &[&BlsMessagePoint<S>],
    pks: &[&BlsPublicKey<S>],
  ) -> Result<(), BlsError> {
    let points: Vec<blst_p2_affine> = msg_points.iter().map(|mp| mp.point).collect();
    let inner_pks: Vec<&S::InnerPk> = pks.iter().map(|pk| &pk.0).collect();
    S::verify_aggregates_prehashed(&self.0, &points, &inner_pks)
  }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "test code")]
mod tests {
  use super::*;
  use crate::bls::{BlsScChia, BlsScIetf, BlsSecretKey};

  use rstest::rstest;

  fn assert_prehashed_matches_verify<S: BlsSchemeId + BlsScheme>() {
    let sk = BlsSecretKey::<S>::generate(&[7u8; 32]).unwrap();
    let pk = sk.public_key();
    let msg = [0x5au8; 32];
    let sig = sk.sign(&msg).unwrap();

    let mp = BlsMessagePoint::<S>::hash(&msg).unwrap();
    assert!(sig.verify_prehashed(&mp, &pk).is_ok());

    let wrong = BlsMessagePoint::<S>::hash(&[0x5bu8; 32]).unwrap();
    assert_eq!(sig.verify_prehashed(&wrong, &pk).unwrap_err(), BlsError::VerifyFailed);

    // Aggregate form: two signers, two distinct messages.
    let sk2 = BlsSecretKey::<S>::generate(&[8u8; 32]).unwrap();
    let msg2 = [0x5cu8; 32];
    let sig2 = sk2.sign(&msg2).unwrap();
    let agg = BlsSignature::aggregate(&[&sig, &sig2]).unwrap();
    let mp2 = BlsMessagePoint::<S>::hash(&msg2).unwrap();
    assert!(agg
      .verify_aggregates_prehashed(&[&mp, &mp2], &[&pk, &sk2.public_key()])
      .is_ok());
    assert!(agg
      .verify_aggregates_prehashed(&[&mp2, &mp], &[&pk, &sk2.public_key()])
      .is_err());
  }

  #[rstest]
  #[case::chia(assert_prehashed_matches_verify::<BlsScChia>)]
  #[case::ietf(assert_prehashed_matches_verify::<BlsScIetf>)]
  fn prehashed_matches_verify(#[case] assertion: fn()) {
    assertion();
  }

  #[test]
  fn ietf_prehashed_aggregate_rejects_duplicate_points() {
    let sk = BlsSecretKey::<BlsScIetf>::generate(&[9u8; 32]).unwrap();
    let pk = sk.public_key();
    let msg = [1u8; 32];
    let sig = sk.sign(&msg).unwrap();
    let agg = BlsSignature::aggregate(&[&sig, &sig]).unwrap();
    let mp = BlsMessagePoint::<BlsScIetf>::hash(&msg).unwrap();
    assert_eq!(
      agg.verify_aggregates_prehashed(&[&mp, &mp], &[&pk, &pk]).unwrap_err(),
      BlsError::DuplicateMessage
    );
  }
}
