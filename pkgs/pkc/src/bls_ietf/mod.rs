//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! IETF BLS12-381 signatures (basic scheme, min-pubkey-size).

use crate::bls::scheme_ops::BlsScheme;
pub use crate::bls::BlsError;
pub type SecretKey = crate::bls::BlsSecretKey<crate::bls::BlsScIetf>;
pub type PublicKey = crate::bls::BlsPublicKey<crate::bls::BlsScIetf>;
pub type Signature = crate::bls::BlsSignature<crate::bls::BlsScIetf>;

impl SecretKey {
  /// Produce a proof of possession by signing the serialized public key with
  /// the PoP DST.
  pub fn prove_possession(&self) -> Signature {
    let pk = crate::bls::BlsScIetf::derive_pk(&self.0);
    Signature::from_inner(
      crate::bls::BlsScIetf::prove_possession(&self.0, &pk).expect("IETF supports proofs of possession"),
    )
  }
}

impl PublicKey {
  /// Verify a proof of possession against this key.
  pub fn verify_possession(&self, pop: &Signature) -> Result<(), BlsError> {
    crate::bls::BlsScIetf::verify_possession(&self.0, &pop.0).map_err(Into::into)
  }
}
