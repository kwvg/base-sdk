//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Common BLS test definitions.

use super::scheme_ops::BlsScheme;
use super::{BlsPublicKey, BlsScChia, BlsScIetf, BlsSchemeId, BlsSecretKey, BlsSigShare, BlsSignature};
use crate::prelude::*;
use crate::tests::{sequential_ids, MSG_DEADBEEF, SEED_0, SEED_1};

use dash_dev::{bls_dh, bls_sign, load_corpus_json};
use hex_literal::hex;
use rand_core::OsRng;
use rstest::rstest;

const SAMPLE_PATTERN: [u8; 6] = hex!("a1b2c3d4e5f6");

const fn repeat_pattern<const N: usize>() -> [u8; N] {
  let mut bytes = [0u8; N];
  let mut i = 0;
  while i < N {
    bytes[i] = SAMPLE_PATTERN[i % SAMPLE_PATTERN.len()];
    i += 1;
  }
  bytes
}

pub(super) const PK_SAMPLE: [u8; 48] = repeat_pattern();
pub(super) const SIG_SAMPLE: [u8; 96] = repeat_pattern();

pub(super) fn assert_dh_roundtrip<S: BlsSchemeId + BlsScheme>() {
  let sk0 = BlsSecretKey::<S>::generate(&SEED_0).unwrap();
  let sk1 = BlsSecretKey::<S>::generate(&SEED_1).unwrap();
  let shared0 = BlsPublicKey::dh_exchange(&sk0, &sk1.public_key()).unwrap();
  let shared1 = BlsPublicKey::dh_exchange(&sk1, &sk0.public_key()).unwrap();
  assert_eq!(shared0, shared1);
}

pub(super) fn assert_sk_roundtrip<S: BlsSchemeId + BlsScheme>() {
  let sk = BlsSecretKey::<S>::generate(&SEED_0).unwrap();
  let restored = BlsSecretKey::<S>::from_bytes(&sk.to_bytes()).unwrap();
  assert_eq!(restored.public_key(), sk.public_key());
}

pub(super) fn assert_short_ikm_rejected<S: BlsSchemeId + BlsScheme>() {
  assert!(BlsSecretKey::<S>::generate(&[0u8; 31]).is_err());
}

pub(super) fn assert_signing_roundtrip<S: BlsSchemeId + BlsScheme>() {
  let sk0 = BlsSecretKey::<S>::generate(&SEED_0).unwrap();
  let sk1 = BlsSecretKey::<S>::generate(&SEED_1).unwrap();
  let sig = sk0.sign(&MSG_DEADBEEF).unwrap();

  assert!(sig.verify(&MSG_DEADBEEF, &sk0.public_key()).is_ok());

  let mut wrong_msg = MSG_DEADBEEF;
  wrong_msg[0] ^= 0xff;
  assert!(sig.verify(&wrong_msg, &sk0.public_key()).is_err());
  assert!(sig.verify(&MSG_DEADBEEF, &sk1.public_key()).is_err());

  assert_eq!(sk0.sign(&MSG_DEADBEEF).unwrap(), sig);
  assert_eq!(BlsSignature::<S>::from_bytes(&sig.to_bytes()).unwrap(), sig);
}

pub(super) fn assert_threshold_roundtrip<S: BlsSchemeId + BlsScheme>() {
  let sk = BlsSecretKey::<S>::generate(&SEED_0).unwrap();
  let ids = sequential_ids(5);
  let shares = sk.split(3, &ids, &mut OsRng).unwrap();
  assert_eq!(shares.len(), ids.len());

  let full_sig = sk.sign(&MSG_DEADBEEF).unwrap();
  let sig_shares: Vec<_> = shares.iter().map(|share| share.sign(&MSG_DEADBEEF).unwrap()).collect();
  let subset: Vec<&BlsSigShare<S>> = [0, 2, 4].into_iter().map(|i| &sig_shares[i]).collect();
  let recovered = BlsSignature::<S>::recover(&subset).unwrap();
  assert_eq!(recovered, full_sig);
}

pub(super) fn assert_insufficient_shares_rejected<S: BlsSchemeId + BlsScheme>() {
  assert!(BlsSignature::<S>::recover(&[]).is_err());
}

pub(super) fn assert_invalid_threshold_rejected<S: BlsSchemeId + BlsScheme>(threshold: usize, total: usize) {
  let sk = BlsSecretKey::<S>::generate(&SEED_0).unwrap();
  assert!(sk.split(threshold, &sequential_ids(total), &mut OsRng).is_err());
}

pub(super) fn assert_empty_aggregation_rejected<S: BlsSchemeId + BlsScheme>() {
  let pks: [&BlsPublicKey<S>; 0] = [];
  let sigs: [&BlsSignature<S>; 0] = [];
  assert!(BlsPublicKey::aggregate(&pks).is_err());
  assert!(BlsSignature::aggregate(&sigs).is_err());
}

pub(super) fn assert_fast_aggregate_verifies<S: BlsSchemeId + BlsScheme>() {
  let sk0 = BlsSecretKey::<S>::generate(&SEED_0).unwrap();
  let sk1 = BlsSecretKey::<S>::generate(&SEED_1).unwrap();
  let sig0 = sk0.sign(&MSG_DEADBEEF).unwrap();
  let sig1 = sk1.sign(&MSG_DEADBEEF).unwrap();
  let aggregate = BlsSignature::aggregate(&[&sig0, &sig1]).unwrap();
  assert!(aggregate
    .fast_verify_aggregates(&MSG_DEADBEEF, &[&sk0.public_key(), &sk1.public_key()])
    .is_ok());
}

pub(super) fn assert_secure_aggregate_rejects_naive<S: BlsSchemeId + BlsScheme>() {
  let sk0 = BlsSecretKey::<S>::generate(&SEED_0).unwrap();
  let sk1 = BlsSecretKey::<S>::generate(&SEED_1).unwrap();
  let sig0 = sk0.sign(&MSG_DEADBEEF).unwrap();
  let sig1 = sk1.sign(&MSG_DEADBEEF).unwrap();
  let aggregate = BlsSignature::aggregate(&[&sig0, &sig1]).unwrap();
  let pk0 = sk0.public_key();
  let pk1 = sk1.public_key();

  assert!(aggregate.fast_verify_aggregates(&MSG_DEADBEEF, &[&pk0, &pk1]).is_ok());
  assert!(aggregate
    .secure_verify_aggregates(&MSG_DEADBEEF, &[&pk0, &pk1])
    .is_err());
}

pub(super) fn assert_aggregate_order_independent<S: BlsSchemeId + BlsScheme>() {
  let sk0 = BlsSecretKey::<S>::generate(&SEED_0).unwrap();
  let sk1 = BlsSecretKey::<S>::generate(&SEED_1).unwrap();
  let sk2 = BlsSecretKey::<S>::generate(&[2u8; 32]).unwrap();
  let sig0 = sk0.sign(&MSG_DEADBEEF).unwrap();
  let sig1 = sk1.sign(&MSG_DEADBEEF).unwrap();
  let sig2 = sk2.sign(&MSG_DEADBEEF).unwrap();
  let aggregate0 = BlsSignature::aggregate(&[&sig0, &sig1, &sig2]).unwrap();
  let aggregate1 = BlsSignature::aggregate(&[&sig2, &sig0, &sig1]).unwrap();
  let pk0 = sk0.public_key();
  let pk1 = sk1.public_key();
  let pk2 = sk2.public_key();

  assert_eq!(aggregate0, aggregate1);
  assert!(aggregate0
    .fast_verify_aggregates(&MSG_DEADBEEF, &[&pk0, &pk1, &pk2])
    .is_ok());
  assert!(aggregate0
    .fast_verify_aggregates(&MSG_DEADBEEF, &[&pk2, &pk0, &pk1])
    .is_ok());
}

fn assert_dh_vectors<S: BlsSchemeId + BlsScheme>(corpus: &str) {
  let corpus = load_corpus_json(env!("CARGO_MANIFEST_DIR"), corpus);
  let vectors = bls_dh(&corpus, "dh_exchange");

  for vector in &vectors {
    let sk = S::sk_from_bytes(&vector.sk).unwrap();
    let peer = S::pk_from_bytes(&vector.peer_pk).unwrap();
    let shared = S::dh_exchange(&sk, &peer).unwrap();
    assert_eq!(S::pk_to_bytes(&shared), vector.shared);
  }
}

#[rstest]
#[case::chia("bls_chia_dh", assert_dh_vectors::<BlsScChia>)]
#[case::ietf("bls_ietf_dh", assert_dh_vectors::<BlsScIetf>)]
fn dh_exchange_matches_vectors(#[case] corpus: &str, #[case] assertion: fn(&str)) {
  assertion(corpus);
}

fn assert_signing_vectors<S: BlsSchemeId + BlsScheme>(corpus: &str) {
  let corpus = load_corpus_json(env!("CARGO_MANIFEST_DIR"), corpus);
  let vectors = bls_sign(&corpus, "sign");

  for vector in &vectors {
    let sk = S::sk_from_bytes(&vector.sk).unwrap();
    let sig = S::sign(&sk, &vector.msg).unwrap();
    assert_eq!(S::sig_to_bytes(&sig), vector.sig);
  }
}

#[rstest]
#[case::chia("bls_chia_sign", assert_signing_vectors::<BlsScChia>)]
#[case::ietf("bls_ietf_sign", assert_signing_vectors::<BlsScIetf>)]
fn signing_matches_vectors(#[case] corpus: &str, #[case] assertion: fn(&str)) {
  assertion(corpus);
}

fn assert_signing_verifies_and_rejects_mismatches<S: BlsSchemeId + BlsScheme>() {
  let sk0 = S::generate(&SEED_0).unwrap();
  let sk1 = S::generate(&SEED_1).unwrap();
  let pk0 = S::derive_pk(&sk0);
  let pk1 = S::derive_pk(&sk1);
  let sig = S::sign(&sk0, &MSG_DEADBEEF).unwrap();

  assert!(S::verify(&sig, &MSG_DEADBEEF, &pk0).is_ok());
  assert!(S::verify(&sig, &[0x42; 32], &pk0).is_err());
  assert!(S::verify(&sig, &MSG_DEADBEEF, &pk1).is_err());
  assert_eq!(
    S::sig_to_bytes(&S::sign(&sk0, &MSG_DEADBEEF).unwrap()),
    S::sig_to_bytes(&sig)
  );
}

#[rstest]
#[case::chia(assert_signing_verifies_and_rejects_mismatches::<BlsScChia>)]
#[case::ietf(assert_signing_verifies_and_rejects_mismatches::<BlsScIetf>)]
fn signing_verifies_and_rejects_mismatches(#[case] assertion: fn()) {
  assertion();
}
