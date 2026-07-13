//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Diffie-Hellman exchange tests for bls_chia.

#![expect(clippy::unwrap_used, reason = "test code")]
#![expect(clippy::panic, reason = "test code")]

mod common;

use dash_pkc::bls_chia::{PublicKey, SecretKey};
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

/// DH exchange produces a shared secret.
#[rstest]
fn dh_exchange_roundtrip(sk_seed0: SecretKey, sk_seed1: SecretKey) {
  let pk0 = sk_seed0.public_key();
  let pk1 = sk_seed1.public_key();
  // sk0 * pk1 == sk1 * pk0
  let shared_a = PublicKey::dh_exchange(&sk_seed0, &pk1).unwrap();
  let shared_b = PublicKey::dh_exchange(&sk_seed1, &pk0).unwrap();
  assert_eq!(shared_a.to_bytes(), shared_b.to_bytes());
}
