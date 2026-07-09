//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Common test definitions.

use crate::ecdsa::{EcdsaPublicKey, EcdsaSecretKey, EcdsaSignature};

use hex_literal::hex;
use rstest::fixture;

pub(super) const ALICE_SK: [u8; 32] = hex!("0123456789abcdef0123456789abcdeffedcba9876543210fedcba9876543210");
pub(super) const MSG: [u8; 32] = hex!("deadbeefdeadbeefdeadbeefdeadbeefcafebabecafebabecafebabecafebabe");

#[fixture]
pub(super) fn alice_pk() -> EcdsaPublicKey {
  alice_sk().public_key()
}

#[fixture]
pub(super) fn alice_sk() -> EcdsaSecretKey {
  EcdsaSecretKey::from_bytes(&ALICE_SK, true).unwrap()
}

#[fixture]
pub(super) fn alice_sig() -> EcdsaSignature {
  alice_sk().sign(&MSG).unwrap()
}
