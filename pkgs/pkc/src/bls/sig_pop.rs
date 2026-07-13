//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Proof of Possession operations for BLS keys.

use super::error::BlsError;
use super::public_ops::BlsPublicKey;
use super::scheme_ops::BlsScheme;
use super::secret_ops::BlsSecretKey;
use super::sig_basic::BlsSignature;
use super::BlsSchemeId;

impl<S: BlsSchemeId + BlsScheme> BlsSecretKey<S> {
  /// Produce a proof of possession by signing the serialized
  /// public key.
  ///
  /// # Errors
  ///
  /// Returns `UnsupportedScheme` for Chia.
  pub fn prove_possession(&self) -> Result<BlsSignature<S>, BlsError> {
    let pk = S::derive_pk(&self.0);
    S::prove_possession(&self.0, &pk).map(BlsSignature::from_inner)
  }
}

impl<S: BlsSchemeId + BlsScheme> BlsPublicKey<S> {
  /// Verify a proof of possession against this key.
  ///
  /// # Errors
  ///
  /// Returns `UnsupportedScheme` for Chia.
  pub fn verify_possession(&self, pop: &BlsSignature<S>) -> Result<(), BlsError> {
    S::verify_possession(&self.0, &pop.0)
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::bls::tests::{SEED_0, SEED_1};
  use crate::bls::BlsScIetf;

  #[test]
  fn proof_of_possession_roundtrip() {
    let sk = BlsSecretKey::<BlsScIetf>::generate(&SEED_0).unwrap();
    let proof = sk.prove_possession().unwrap();
    assert!(sk.public_key().verify_possession(&proof).is_ok());
  }

  #[test]
  fn proof_of_possession_rejects_wrong_key() {
    let sk0 = BlsSecretKey::<BlsScIetf>::generate(&SEED_0).unwrap();
    let sk1 = BlsSecretKey::<BlsScIetf>::generate(&SEED_1).unwrap();
    let proof = sk0.prove_possession().unwrap();
    assert!(sk1.public_key().verify_possession(&proof).is_err());
  }
}
