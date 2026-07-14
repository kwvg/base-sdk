//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Verification vectors (Feldman polynomial commitments).

use super::error::BlsError;
use super::public_ops::BlsPublicKey;
use super::scheme_ops::{self, BlsScheme};
use super::secret_ops::BlsSecretKey;
use super::share_ops::{BlsPkShare, BlsSkShare};
use super::BlsSchemeId;
use crate::prelude::*;

use dash_num::Hash256;
use rand_core::CryptoRngCore;

use core::fmt::{Debug, Formatter, Result as FmtResult};

/// A verification vector: the secret-sharing polynomial's
/// coefficients committed as public keys.
///
/// Entry 0 commits to the constant term, i.e. the master public
/// key. Evaluating the vector at a participant id yields that
/// participant's public key share (Feldman VSS).
pub struct BlsVerificationVector<S: BlsSchemeId + BlsScheme>(Vec<BlsPublicKey<S>>);

impl<S: BlsSchemeId + BlsScheme> Clone for BlsVerificationVector<S> {
  fn clone(&self) -> Self {
    Self(self.0.clone())
  }
}

impl<S: BlsSchemeId + BlsScheme> PartialEq for BlsVerificationVector<S> {
  fn eq(&self, other: &Self) -> bool {
    self.0 == other.0
  }
}

impl<S: BlsSchemeId + BlsScheme> Eq for BlsVerificationVector<S> {}

impl<S: BlsSchemeId + BlsScheme> BlsVerificationVector<S> {
  /// Construct from committed coefficient public keys.
  ///
  /// Mirrors `CBLSWorker::VerifyVerificationVector`: at least 2
  /// entries (threshold >= 2) and no duplicate entries.
  ///
  /// # Errors
  ///
  /// Returns `InvalidVerificationVector` on a short vector or
  /// duplicate entries.
  pub fn new(entries: Vec<BlsPublicKey<S>>) -> Result<Self, BlsError> {
    if entries.len() < 2 {
      return Err(BlsError::InvalidVerificationVector);
    }
    let mut sorted: Vec<[u8; 48]> = entries.iter().map(BlsPublicKey::to_bytes).collect();
    sorted.sort_unstable();
    if sorted.windows(2).any(|pair| pair[0] == pair[1]) {
      return Err(BlsError::InvalidVerificationVector);
    }
    Ok(Self(entries))
  }

  /// The recovery threshold this commitment encodes.
  pub fn threshold(&self) -> usize {
    self.0.len()
  }

  /// The committed coefficient public keys.
  pub fn entries(&self) -> &[BlsPublicKey<S>] {
    &self.0
  }

  /// The master public key (commitment to the constant term).
  pub fn master_public_key(&self) -> &BlsPublicKey<S> {
    &self.0[0]
  }

  /// Evaluate the committed polynomial at a participant id,
  /// yielding that participant's public key share
  /// (`CBLSWorker::BuildPubKeyShare`).
  ///
  /// # Errors
  ///
  /// Returns `InvalidShareId` if the id reduces to zero in the
  /// scalar field.
  pub fn derive_pk_share(&self, id: Hash256) -> Result<BlsPkShare<S>, BlsError> {
    let refs: Vec<&BlsPublicKey<S>> = self.0.iter().collect();
    BlsPkShare::derive(&refs, id)
  }

  /// Verify a dealer's secret key share against this commitment
  /// (Feldman VSS, `CBLSWorker::VerifyContributionShare`): the
  /// share is valid iff the polynomial evaluated at the
  /// recipient id equals the share's public key.
  ///
  /// # Errors
  ///
  /// Returns `VerifyFailed` when the share does not lie on the
  /// committed polynomial, or an id reduction error.
  pub fn verify_contribution(&self, share: &BlsSkShare<S>) -> Result<(), BlsError> {
    let expected = self.derive_pk_share(*share.id())?;
    if *expected.public_key() == share.secret_key().public_key() {
      Ok(())
    } else {
      Err(BlsError::VerifyFailed)
    }
  }

  /// Component-wise sum of member verification vectors,
  /// producing the quorum's aggregate commitment
  /// (`CBLSWorker::BuildQuorumVerificationVector`).
  ///
  /// # Errors
  ///
  /// Returns `EmptyAggregation` without inputs, `CountMismatch`
  /// on non-uniform lengths, or an aggregation error.
  pub fn aggregate(vvecs: &[&Self]) -> Result<Self, BlsError> {
    let (first, rest) = vvecs.split_first().ok_or(BlsError::EmptyAggregation)?;
    if rest.iter().any(|v| v.threshold() != first.threshold()) {
      return Err(BlsError::CountMismatch);
    }

    let mut entries = Vec::with_capacity(first.threshold());
    for k in 0..first.threshold() {
      let column: Vec<&BlsPublicKey<S>> = vvecs.iter().map(|v| &v.0[k]).collect();
      entries.push(BlsPublicKey::aggregate(&column)?);
    }
    Ok(Self(entries))
  }
}

impl<S: BlsSchemeId + BlsScheme> Debug for BlsVerificationVector<S> {
  fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
    write!(f, "BlsVerificationVector<{}>(threshold={})", S::LABEL, self.0.len())
  }
}

impl<S: BlsSchemeId + BlsScheme> BlsSecretKey<S> {
  /// Split this secret key into shares along with the Feldman
  /// commitment to the sharing polynomial
  /// (`CBLSWorker::GenerateContributions` with this key as the
  /// constant term).
  ///
  /// # Errors
  ///
  /// As [`BlsSecretKey::split`].
  pub fn split_with_commitment(
    &self,
    threshold: usize,
    ids: &[Hash256],
    rng: &mut impl CryptoRngCore,
  ) -> Result<(BlsVerificationVector<S>, Vec<BlsSkShare<S>>), BlsError> {
    if threshold < 2 || ids.is_empty() || threshold > ids.len() {
      return Err(BlsError::ThresholdTooLarge);
    }

    let id_refs: Vec<&Hash256> = ids.iter().collect();
    scheme_ops::reduce_share_ids(&id_refs)?;

    let (raw, coeffs) =
      scheme_ops::generate_shares(&self.to_bytes(), threshold, ids, rng).map_err(|()| BlsError::InvalidSecretKey)?;

    let commitments: Vec<BlsPublicKey<S>> = coeffs
      .iter()
      .map(|bytes| Ok(BlsSecretKey::<S>::from_bytes(bytes)?.public_key()))
      .collect::<Result<_, BlsError>>()?;
    let vvec = BlsVerificationVector::new(commitments)?;

    let shares = raw
      .into_iter()
      .map(|(id, bytes)| {
        let share_sk = BlsSecretKey::<S>::from_bytes(&bytes).map_err(|_| BlsError::InvalidSecretKey)?;
        Ok(BlsSkShare::new(id, share_sk))
      })
      .collect::<Result<Vec<_>, BlsError>>()?;

    Ok((vvec, shares))
  }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "test code")]
mod tests {
  use super::*;
  use crate::bls::{BlsScChia, BlsScIetf, BlsSignature};
  use crate::tests::*;

  use rand_core::OsRng;
  use rstest::rstest;

  fn assert_contribution_flow<S: BlsSchemeId + BlsScheme>() {
    // A full DKG-style contribution: split with commitment,
    // verify every share against the vector, derive pk shares,
    // and check the committed master pk.
    let sk = BlsSecretKey::<S>::generate(&SEED_0).unwrap();
    let ids = sequential_ids(5);
    let (vvec, shares) = sk.split_with_commitment(3, &ids, &mut OsRng).unwrap();

    assert_eq!(vvec.threshold(), 3);
    assert_eq!(*vvec.master_public_key(), sk.public_key());

    for share in &shares {
      assert!(vvec.verify_contribution(share).is_ok());
      let pk_share = vvec.derive_pk_share(*share.id()).unwrap();
      assert_eq!(pk_share, share.public_key_share());

      let sig_share = share.sign(&MSG_DEADBEEF).unwrap();
      assert!(pk_share.verify(&sig_share, &MSG_DEADBEEF).is_ok());
    }

    // A share that does not lie on the polynomial is rejected.
    let stranger = BlsSecretKey::<S>::generate(&SEED_1).unwrap();
    let bogus = BlsSkShare::new(ids[0], stranger);
    assert_eq!(vvec.verify_contribution(&bogus).unwrap_err(), BlsError::VerifyFailed);
  }

  #[rstest]
  #[case::chia(assert_contribution_flow::<BlsScChia>)]
  #[case::ietf(assert_contribution_flow::<BlsScIetf>)]
  fn contribution_flow(#[case] assertion: fn()) {
    assertion();
  }

  fn assert_quorum_vvec_aggregation<S: BlsSchemeId + BlsScheme>() {
    // Two dealers contribute; the quorum vvec is the
    // component-wise sum, member secret key shares are the sums
    // of the received shares, and the quorum pk share matches.
    let ids = sequential_ids(4);
    let sk_a = BlsSecretKey::<S>::generate(&SEED_0).unwrap();
    let sk_b = BlsSecretKey::<S>::generate(&SEED_1).unwrap();
    let (vvec_a, shares_a) = sk_a.split_with_commitment(3, &ids, &mut OsRng).unwrap();
    let (vvec_b, shares_b) = sk_b.split_with_commitment(3, &ids, &mut OsRng).unwrap();

    let quorum_vvec = BlsVerificationVector::aggregate(&[&vvec_a, &vvec_b]).unwrap();
    assert_eq!(quorum_vvec.threshold(), 3);

    for (share_a, share_b) in shares_a.iter().zip(&shares_b) {
      let member_sk = BlsSecretKey::aggregate(&[share_a.secret_key(), share_b.secret_key()]).unwrap();
      let member_share = BlsSkShare::new(*share_a.id(), member_sk);
      assert!(quorum_vvec.verify_contribution(&member_share).is_ok());
    }

    // Recovery under the quorum key: sign with 3 member shares
    // and verify against the aggregated master pk.
    let members: Vec<BlsSkShare<S>> = shares_a
      .iter()
      .zip(&shares_b)
      .take(3)
      .map(|(a, b)| {
        let sk = BlsSecretKey::aggregate(&[a.secret_key(), b.secret_key()]).unwrap();
        BlsSkShare::new(*a.id(), sk)
      })
      .collect();
    let sig_shares: Vec<_> = members.iter().map(|m| m.sign(&MSG_DEADBEEF).unwrap()).collect();
    let share_refs: Vec<_> = sig_shares.iter().collect();
    let recovered = BlsSignature::recover(&share_refs).unwrap();
    assert!(recovered.verify(&MSG_DEADBEEF, quorum_vvec.master_public_key()).is_ok());

    // Mismatched lengths are rejected.
    let (short_vvec, _) = sk_a.split_with_commitment(2, &ids, &mut OsRng).unwrap();
    assert_eq!(
      BlsVerificationVector::aggregate(&[&vvec_a, &short_vvec]).unwrap_err(),
      BlsError::CountMismatch
    );
  }

  #[rstest]
  #[case::chia(assert_quorum_vvec_aggregation::<BlsScChia>)]
  #[case::ietf(assert_quorum_vvec_aggregation::<BlsScIetf>)]
  fn quorum_vvec_aggregation(#[case] assertion: fn()) {
    assertion();
  }

  #[rstest]
  fn rejects_short_and_duplicate_vectors() {
    let sk = BlsSecretKey::<BlsScIetf>::generate(&SEED_0).unwrap();
    let pk = sk.public_key();
    assert_eq!(
      BlsVerificationVector::new(vec![pk.clone()]).unwrap_err(),
      BlsError::InvalidVerificationVector
    );
    assert_eq!(
      BlsVerificationVector::new(vec![pk.clone(), pk]).unwrap_err(),
      BlsError::InvalidVerificationVector
    );
  }
}
