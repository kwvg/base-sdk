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
