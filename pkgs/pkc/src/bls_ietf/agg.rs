//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Aggregation and batch verification for IETF BLS.

use super::{PublicKey, SecretKey, Signature};
use crate::bls::BlsError;

/// Aggregate multiple public keys into one.
pub fn aggregate_pk(keys: &[&PublicKey]) -> Result<PublicKey, BlsError> {
  PublicKey::aggregate(keys)
}

/// Aggregate multiple signatures into one.
pub fn aggregate_sig(sigs: &[&Signature]) -> Result<Signature, BlsError> {
  Signature::aggregate(sigs)
}

/// Verify an aggregated signature where every signer signed the same message.
pub fn fast_verify_aggregates(sig: &Signature, msg: &[u8], pks: &[&PublicKey]) -> Result<(), BlsError> {
  sig.fast_verify_aggregates(msg, pks)
}

/// Sum multiple secret keys (mod group order).
pub fn aggregate_sk(keys: &[&SecretKey]) -> Result<SecretKey, BlsError> {
  SecretKey::aggregate(keys)
}
