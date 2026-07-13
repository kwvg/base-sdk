//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Aggregation and secure verification for legacy BLS.

use super::sig::Signature;
use super::sk::SecretKey;
use super::PublicKey;
use crate::bls::scheme_ops::BlsScheme;
use crate::bls::{BlsError, BlsScChia};
use crate::prelude::*;

/// Aggregate multiple legacy BLS public keys (simple point addition in G1).
pub fn aggregate_pk(keys: &[&PublicKey]) -> Result<PublicKey, BlsError> {
  let inner: Vec<_> = keys.iter().map(|key| &key.0).collect();
  BlsScChia::aggregate_pk(&inner).map(PublicKey::from_inner)
}

/// Aggregate multiple legacy BLS signatures (simple point addition in G2).
pub fn aggregate_sig(sigs: &[&Signature]) -> Result<Signature, BlsError> {
  let inner: Vec<_> = sigs.iter().map(|sig| &sig.0).collect();
  BlsScChia::aggregate_sig(&inner).map(Signature::from_inner)
}

/// Verify an aggregated legacy BLS signature over one message and multiple
/// public keys.
pub fn verify_aggregates(sig: &Signature, msg: &[u8; 32], pks: &[&PublicKey]) -> Result<(), BlsError> {
  let inner: Vec<_> = pks.iter().map(|pk| &pk.0).collect();
  BlsScChia::fast_verify_aggregates(&sig.0, msg, &inner)
}

/// Verify an aggregated legacy BLS signature where every signer signed the
/// same message. Equivalent to `verify_aggregates` for the legacy scheme.
pub fn fast_verify_aggregates(sig: &Signature, msg: &[u8; 32], pks: &[&PublicKey]) -> Result<(), BlsError> {
  let inner: Vec<_> = pks.iter().map(|pk| &pk.0).collect();
  BlsScChia::fast_verify_aggregates(&sig.0, msg, &inner)
}

/// Securely aggregate and verify signatures with public-key weighting.
///
/// Algorithm:
/// 1. Sort public keys by serialized (legacy) bytes
/// 2. Compute `pk_hash = SHA256(pk1 || pk2 || ... || pkN)` (sorted order)
/// 3. For each sorted pk at index i: `weight_i = SHA256(i_as_4_bytes ||
///    pk_hash) mod order`
/// 4. Compute weighted public key: `agg_pk = sum(weight_i * pk_i)`
/// 5. Verify the aggregate signature against `agg_pk` and the message
pub fn secure_verify_aggregates(sig: &Signature, msg: &[u8; 32], pks: &[&PublicKey]) -> Result<(), BlsError> {
  let inner: Vec<_> = pks.iter().map(|pk| &pk.0).collect();
  BlsScChia::secure_verify_aggregates(&sig.0, msg, &inner)
}

/// Sum multiple secret keys (mod group order).
pub fn aggregate_sk(keys: &[&SecretKey]) -> Result<SecretKey, BlsError> {
  let inner: Vec<_> = keys.iter().map(|key| &key.0).collect();
  BlsScChia::aggregate_sk(&inner).map(SecretKey)
}
