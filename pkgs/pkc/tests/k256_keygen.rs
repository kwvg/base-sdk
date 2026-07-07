//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Key generation and public key serialization tests for k256.

#![expect(clippy::unwrap_used, reason = "test code")]
#![expect(clippy::panic, reason = "test code")]

mod common;

use dash_pkc::ecdsa::{EcdsaPublicKey, EcdsaSecretKey};
use hex_literal::hex;
use rstest::*;

/// Shared test keypair.
#[fixture]
fn alice() -> EcdsaSecretKey {
  EcdsaSecretKey::from_bytes(&hex!(
    "0123456789abcdef0123456789abcdef"
    "fedcba9876543210fedcba9876543210"
  ))
  .unwrap()
}

/// Secret key serialization round-trips.
#[rstest]
fn from_bytes_roundtrip(alice: EcdsaSecretKey) {
  let bytes = alice.to_bytes();
  let restored = EcdsaSecretKey::from_bytes(&bytes).unwrap();
  assert_eq!(restored.public_key().to_bytes(), alice.public_key().to_bytes());
}

/// Zero scalar is rejected.
#[rstest]
fn from_bytes_rejects_zero() {
  assert!(EcdsaSecretKey::from_bytes(&[0u8; 32]).is_err());
}

/// Compressed public key round-trips through SEC1.
#[rstest]
fn pubkey_compressed_roundtrip(alice: EcdsaSecretKey) {
  let pk = alice.public_key();
  let bytes = pk.to_bytes();
  assert_eq!(bytes.len(), 33);
  let restored = EcdsaPublicKey::from_bytes(&bytes).unwrap();
  assert_eq!(restored, pk);
}

/// Uncompressed public key round-trips through SEC1.
#[rstest]
fn pubkey_uncompressed_roundtrip(alice: EcdsaSecretKey) {
  let pk = alice.public_key();
  let bytes = pk.to_uncompressed_bytes();
  assert_eq!(bytes.len(), 65);
  let restored = EcdsaPublicKey::from_bytes(&bytes).unwrap();
  assert_eq!(restored, pk);
}

/// Garbage bytes are rejected.
#[rstest]
fn pubkey_rejects_garbage() {
  assert!(EcdsaPublicKey::from_bytes(&[0xff; 33]).is_err());
}

/// Serde round-trip for EcdsaPublicKey.
#[cfg(feature = "serde")]
#[rstest]
fn serde_pk_roundtrip(alice: EcdsaSecretKey) {
  let pk = alice.public_key();
  let json = serde_json::to_string(&pk).unwrap();
  let restored: EcdsaPublicKey = serde_json::from_str(&json).unwrap();
  assert_eq!(restored, pk);
}

mod kat {
  use super::common::{self, decode_hex, VectorFile};

  use hex_conservative::DisplayHex;
  use serde::Deserialize;

  #[derive(Deserialize)]
  struct KeygenVector {
    sk: String,
    pk_compressed: String,
  }

  #[test]
  fn kat_derive_pk() {
    let f: VectorFile = common::load("k256_keygen");
    let vecs: Vec<KeygenVector> = common::parse_sub(&f, "derive_pk");

    for v in &vecs {
      let sk_bytes: [u8; 32] = decode_hex(&v.sk).try_into().unwrap();
      let sk = dash_pkc::ecdsa::EcdsaSecretKey::from_bytes(&sk_bytes).unwrap();
      let pk = sk.public_key();
      assert_eq!(
        pk.to_bytes().to_lower_hex_string(),
        v.pk_compressed,
        "pk mismatch for sk {}",
        v.sk
      );
    }
  }
}
