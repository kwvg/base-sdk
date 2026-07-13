//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Signing and verification tests for bls_chia.

#![expect(clippy::unwrap_used, reason = "test code")]
#![expect(clippy::panic, reason = "test code")]

mod common;

use dash_pkc::bls_chia::{SecretKey, Signature};
use rstest::*;

/// Key derived from all-zero IKM.
#[fixture]
fn sk_seed0() -> SecretKey {
  SecretKey::generate(&common::SEED_0).unwrap()
}

/// Key derived from all-one IKM.
#[fixture]
fn sk_seed1() -> SecretKey {
  SecretKey::generate(&common::SEED_1).unwrap()
}

/// Shared 32-byte test message.
#[fixture]
fn msg32() -> [u8; 32] {
  common::MSG_DEADBEEF
}

/// Sign then verify round-trips.
#[rstest]
fn sign_verify_roundtrip(sk_seed0: SecretKey, msg32: [u8; 32]) {
  let sig = sk_seed0.sign(&msg32);
  let pk = sk_seed0.public_key();
  assert!(sig.verify(&msg32, &pk).is_ok());
}

/// Verification rejects a tampered message.
#[rstest]
fn verify_rejects_wrong_message(sk_seed0: SecretKey, msg32: [u8; 32]) {
  let sig = sk_seed0.sign(&msg32);
  let mut bad = msg32;
  bad[0] ^= 0xff;
  assert!(sig.verify(&bad, &sk_seed0.public_key()).is_err());
}

/// Verification rejects a different signer's key.
#[rstest]
fn verify_rejects_wrong_key(sk_seed0: SecretKey, sk_seed1: SecretKey, msg32: [u8; 32]) {
  let sig = sk_seed0.sign(&msg32);
  assert!(sig.verify(&msg32, &sk_seed1.public_key()).is_err());
}

/// Legacy BLS signing is deterministic.
#[rstest]
fn sign_is_deterministic(sk_seed0: SecretKey, msg32: [u8; 32]) {
  let sig1 = sk_seed0.sign(&msg32);
  let sig2 = sk_seed0.sign(&msg32);
  assert_eq!(sig1, sig2);
}

/// Legacy signature round-trips (96 bytes).
#[rstest]
fn sig_roundtrip(sk_seed0: SecretKey, msg32: [u8; 32]) {
  let sig = sk_seed0.sign(&msg32);
  let bytes = sig.to_bytes();
  assert_eq!(bytes.len(), 96);
  let restored = Signature::from_bytes(&bytes).unwrap();
  assert_eq!(restored, sig);
}

/// Serde round-trip for Signature.
#[cfg(feature = "serde")]
#[rstest]
fn serde_sig_roundtrip(sk_seed0: SecretKey, msg32: [u8; 32]) {
  let sig = sk_seed0.sign(&msg32);
  let json = serde_json::to_string(&sig).unwrap();
  let restored: Signature = serde_json::from_str(&json).unwrap();
  assert_eq!(restored, sig);
}

/// Same signature serialized under legacy and IETF formats
/// must produce different bytes.
#[rstest]
fn cross_format_sig_differs(sk_seed0: SecretKey, msg32: [u8; 32]) {
  let legacy_sig = sk_seed0.sign(&msg32).to_bytes();
  let ietf_sk = dash_pkc::bls_ietf::SecretKey::from_bytes(&sk_seed0.to_bytes()).unwrap();
  let ietf_sig = ietf_sk.sign(&msg32).to_bytes();
  assert_ne!(legacy_sig, ietf_sig, "same point must serialize differently");
}

/// Same key material produces different signatures under legacy
/// and IETF schemes (different hash-to-G2).
#[rstest]
fn legacy_sig_differs_from_ietf() {
  let ikm = [0u8; 32];
  let legacy_sk = dash_pkc::bls_chia::SecretKey::generate(&ikm).unwrap();
  let ietf_sk = dash_pkc::bls_ietf::SecretKey::generate(&ikm).unwrap();
  assert_eq!(legacy_sk.to_bytes(), ietf_sk.to_bytes());

  let msg = [0x42u8; 32];
  let legacy_sig = legacy_sk.sign(&msg);
  let ietf_sig = ietf_sk.sign(&msg);
  assert_ne!(legacy_sig.to_bytes(), ietf_sig.to_bytes());
}

/// Same curve point, different wire format.
#[rstest]
fn legacy_pk_serialization_differs_from_ietf() {
  let ikm = [0u8; 32];
  let legacy_pk = dash_pkc::bls_chia::SecretKey::generate(&ikm).unwrap().public_key();
  let ietf_pk = dash_pkc::bls_ietf::SecretKey::generate(&ikm).unwrap().public_key();
  assert_ne!(legacy_pk.to_bytes(), ietf_pk.to_bytes());
}
