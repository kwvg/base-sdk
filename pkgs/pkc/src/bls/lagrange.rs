//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Precomputed Lagrange coefficients for repeated recovery.

use crate::bls::blst_ffi::Fr;
use crate::bls::error::BlsError;
use crate::bls::scheme_ops::{self, BlsScheme};
use crate::bls::schemes::BlsSchemeId;
use crate::bls::sig_basic::BlsSignature;
use crate::prelude::*;

use blst::blst_p2_affine;
use dash_num::Hash256;

/// Lagrange coefficients at x=0 for a fixed, ordered participant
/// id set.
///
/// Coefficient derivation (reduction, batch inversion) is a pure
/// function of the id set; callers recovering many signatures with
/// the same member set can compute it once and use
/// [`BlsSignature::recover_with_coefficients`].
#[derive(Clone)]
pub struct BlsLagrangeCoefficients {
  coeffs: Vec<Fr>,
}

impl BlsLagrangeCoefficients {
  /// Compute coefficients for the given ordered ids.
  ///
  /// # Errors
  ///
  /// Returns `InsufficientShares` with fewer than 2 ids, or a
  /// share id reduction error (zero or duplicate ids).
  pub fn new(ids: &[&Hash256]) -> Result<Self, BlsError> {
    if ids.len() < 2 {
      return Err(BlsError::InsufficientShares);
    }
    let fr_ids = scheme_ops::reduce_share_ids(ids)?;
    Ok(Self {
      coeffs: scheme_ops::compute_lagrange_coeffs(&fr_ids),
    })
  }

  /// Number of participant ids the coefficients cover.
  pub fn len(&self) -> usize {
    self.coeffs.len()
  }

  /// True when no coefficients are held (never for constructed
  /// values; `new` requires at least two ids).
  pub fn is_empty(&self) -> bool {
    self.coeffs.is_empty()
  }
}

impl core::fmt::Debug for BlsLagrangeCoefficients {
  fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
    write!(f, "BlsLagrangeCoefficients(n={})", self.coeffs.len())
  }
}

impl<S: BlsSchemeId + BlsScheme> BlsSignature<S> {
  /// Recover a threshold signature from shares ordered exactly as
  /// the ids that produced `coeffs`; equivalent to [`Self::recover`]
  /// over the same (id, share) pairs.
  ///
  /// # Errors
  ///
  /// Returns `CountMismatch` when the share count differs from the
  /// coefficient count, or `InvalidSignature` when the result is
  /// the point at infinity.
  pub fn recover_with_coefficients(coeffs: &BlsLagrangeCoefficients, sigs: &[&Self]) -> Result<Self, BlsError> {
    if sigs.len() != coeffs.coeffs.len() {
      return Err(BlsError::CountMismatch);
    }
    let mut points: Vec<blst_p2_affine> = Vec::with_capacity(sigs.len());
    for sig in sigs {
      points.push(S::sig_to_affine(&sig.0)?);
    }
    let aff = scheme_ops::interpolate_g2_with_coeffs(&coeffs.coeffs, &points);
    S::sig_from_affine(aff).map(Self::from_inner)
  }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "test code")]
mod tests {
  use super::*;
  use crate::bls::{BlsPublicKey, BlsScChia, BlsScIetf, BlsSecretKey, BlsSigShare};

  use rand_core::OsRng;
  use rstest::rstest;

  fn assert_equivalences<S: BlsSchemeId + BlsScheme>() {
    let sk = BlsSecretKey::<S>::generate(&[3u8; 32]).unwrap();
    let ids: Vec<Hash256> = (1u8..=5).map(|i| Hash256::from_bytes([i; 32])).collect();
    let shares = sk.split(3, &ids, &mut OsRng).unwrap();
    let msg = [0x42u8; 32];

    // recover_with_coefficients must match plain recover over the
    // same ordered (id, share) pairs.
    let sig_shares: Vec<BlsSigShare<S>> = shares[..3].iter().map(|sh| sh.sign(&msg).unwrap()).collect();
    let share_refs: Vec<&BlsSigShare<S>> = sig_shares.iter().collect();
    let plain = BlsSignature::recover(&share_refs).unwrap();

    let id_refs: Vec<&Hash256> = sig_shares.iter().map(|sh| sh.id()).collect();
    let coeffs = BlsLagrangeCoefficients::new(&id_refs).unwrap();
    let sigs: Vec<&BlsSignature<S>> = sig_shares.iter().map(|sh| sh.signature()).collect();
    let cached = BlsSignature::recover_with_coefficients(&coeffs, &sigs).unwrap();
    assert_eq!(plain, cached);

    assert_eq!(
      BlsSignature::<S>::recover_with_coefficients(&coeffs, &sigs[..2]).unwrap_err(),
      BlsError::CountMismatch
    );

    // aggregate_secure must be the key that secure-aggregated
    // signatures verify against with a plain verify.
    let sks: Vec<BlsSecretKey<S>> = (10u8..13).map(|i| BlsSecretKey::generate(&[i; 32]).unwrap()).collect();
    let pks: Vec<BlsPublicKey<S>> = sks.iter().map(BlsSecretKey::public_key).collect();
    let pk_refs: Vec<&BlsPublicKey<S>> = pks.iter().collect();
    let member_sigs: Vec<BlsSignature<S>> = sks.iter().map(|k| k.sign(&msg).unwrap()).collect();
    let sig_refs: Vec<&BlsSignature<S>> = member_sigs.iter().collect();
    let secure = BlsSignature::aggregate_secure(&sig_refs, &pk_refs).unwrap();
    assert!(secure.secure_verify_aggregates(&msg, &pk_refs).is_ok());

    let agg_pk = BlsPublicKey::aggregate_secure(&pk_refs).unwrap();
    assert!(secure.verify(&msg, &agg_pk).is_ok());
    assert!(plain.verify(&msg, &agg_pk).is_err());
  }

  #[rstest]
  #[case::chia(assert_equivalences::<BlsScChia>)]
  #[case::ietf(assert_equivalences::<BlsScIetf>)]
  fn cached_primitives_match_plain(#[case] assertion: fn()) {
    assertion();
  }
}
