//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Signing and verification tests for bls_ietf.

#![expect(clippy::unwrap_used, reason = "test code")]
#![expect(clippy::panic, reason = "test code")]

mod common;

use dash_pkc::bls_ietf::{SecretKey, Signature};
use hex_literal::hex;
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

/// Sign then verify with a generated key succeeds and is
/// deterministic.
#[rstest]
fn sign_verify_known_key() {
  let sk = SecretKey::generate(&common::SEED_0).unwrap();
  let msg = hex!("070809");
  let sig = sk.sign(&msg);
  assert!(sig.verify(&msg, &sk.public_key()).is_ok());
  assert_eq!(sk.sign(&msg).to_bytes(), sig.to_bytes());
}

/// Sign then verify round-trips.
#[rstest]
fn sign_verify_roundtrip(sk_seed0: SecretKey) {
  let msg = b"hello dash";
  let sig = sk_seed0.sign(msg);
  assert!(sig.verify(msg, &sk_seed0.public_key()).is_ok());
}

/// Verification rejects a tampered message.
#[rstest]
fn verify_rejects_wrong_message(sk_seed0: SecretKey) {
  let sig = sk_seed0.sign(b"right");
  assert!(sig.verify(b"wrong", &sk_seed0.public_key()).is_err());
}

/// Verification rejects a different signer's key.
#[rstest]
fn verify_rejects_wrong_key(sk_seed0: SecretKey, sk_seed1: SecretKey) {
  let sig = sk_seed0.sign(b"msg");
  assert!(sig.verify(b"msg", &sk_seed1.public_key()).is_err());
}

/// Compressed signature round-trips (96 bytes).
#[rstest]
fn sig_roundtrip(sk_seed0: SecretKey) {
  let sig = sk_seed0.sign(b"test");
  let bytes = sig.to_bytes();
  assert_eq!(bytes.len(), 96);
  let restored = Signature::from_bytes(&bytes).unwrap();
  assert_eq!(restored, sig);
}

/// BLS signing is deterministic.
#[rstest]
fn sign_is_deterministic(sk_seed0: SecretKey) {
  let msg = b"determinism check";
  let sig1 = sk_seed0.sign(msg);
  let sig2 = sk_seed0.sign(msg);
  assert_eq!(sig1, sig2);
}

/// Serde round-trip for Signature.
#[cfg(feature = "serde")]
#[rstest]
fn serde_sig_roundtrip(sk_seed0: SecretKey) {
  let sig = sk_seed0.sign(b"serde test");
  let json = serde_json::to_string(&sig).unwrap();
  let restored: Signature = serde_json::from_str(&json).unwrap();
  assert_eq!(restored, sig);
}

/// Same signature under IETF and legacy formats must differ.
#[rstest]
fn cross_format_sig_differs(sk_seed0: SecretKey) {
  let msg = b"cross-format test";
  let ietf_sig = sk_seed0.sign(msg).to_bytes();
  // Legacy sign requires [u8; 32], use a padded version.
  let mut msg32 = [0u8; 32];
  msg32[..msg.len()].copy_from_slice(msg);
  let legacy_sk = dash_pkc::bls_chia::SecretKey::from_bytes(&sk_seed0.to_bytes()).unwrap();
  let legacy_sig = legacy_sk.sign(&msg32).to_bytes();
  assert_ne!(ietf_sig, legacy_sig, "same key must produce different sigs");
}
