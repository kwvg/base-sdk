//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Proof of possession tests for bls_ietf.

#![expect(clippy::unwrap_used, reason = "test code")]
#![expect(clippy::panic, reason = "test code")]

mod common;

use dash_pkc::bls_ietf::SecretKey;
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

/// Proof of possession round-trips.
#[rstest]
fn pop_prove_verify(sk_seed0: SecretKey) {
  let pop = sk_seed0.prove_possession().unwrap();
  let pk = sk_seed0.public_key();
  assert!(pk.verify_possession(&pop).is_ok());
}

/// PoP from a different key is rejected.
#[rstest]
fn pop_rejects_wrong_key(sk_seed0: SecretKey, sk_seed1: SecretKey) {
  let pop = sk_seed0.prove_possession().unwrap();
  let wrong_pk = sk_seed1.public_key();
  assert!(wrong_pk.verify_possession(&pop).is_err());
}
