//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Serialization format KAT tests for bls_chia.

#![expect(clippy::unwrap_used, reason = "test code")]
#![expect(clippy::panic, reason = "test code")]

mod common;

mod kat {
  use super::common::{self, decode_hex, VectorFile};

  use hex_conservative::DisplayHex;
  use serde::Deserialize;

  #[derive(Deserialize)]
  struct SerInternalVector {
    pk_legacy: String,
    pk_ietf: String,
  }

  /// Validate that the same G1 point serializes differently
  /// under legacy vs IETF formats.
  #[test]
  fn kat_ser_pk_formats() {
    let f: VectorFile = common::load("bls_chia_ser_internals");
    let vecs: Vec<SerInternalVector> = common::parse_sub(&f, "pk_serialization");

    for v in &vecs {
      // Legacy bytes should deserialize and re-serialize
      // identically.
      let legacy_bytes: [u8; 48] = decode_hex(&v.pk_legacy).try_into().unwrap();
      let pk = dash_pkc::bls_chia::PublicKey::from_bytes(&legacy_bytes).unwrap();
      assert_eq!(
        pk.to_bytes().to_lower_hex_string(),
        v.pk_legacy,
        "legacy pk roundtrip mismatch"
      );

      // The two formats must differ for the same point.
      assert_ne!(v.pk_legacy, v.pk_ietf, "legacy and ietf should differ");
    }
  }
}
