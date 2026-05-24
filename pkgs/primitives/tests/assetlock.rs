//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! KAT tests for AssetLock.

#![expect(clippy::unwrap_used, reason = "test code")]

mod util;

use dash_primitives::payload::AssetLock;
use hex_conservative::FromHex;
use rstest::rstest;

#[rstest]
fn decode_fields() {
  let corpus = util::load_transactions("assetlock");
  for (txid, entry) in &corpus {
    util::assert_txid(&entry.raw, txid);
    let tx = util::decode_tx(&entry.raw);
    assert!(tx.validate(&Default::default()).is_ok());
    assert!(!tx.extra_payload.is_empty(), "{txid}");

    let payload = AssetLock::decode(&mut &tx.extra_payload[..]).unwrap();
    assert!(payload.validate(&Default::default()).is_ok());
    let d = &entry.details;

    assert_eq!(payload.version, util::json_u64(&d["version"]) as u8, "{txid}",);

    let expected_outputs = d["creditOutputs"].as_array().unwrap();
    assert_eq!(payload.credit_outputs.len(), expected_outputs.len(), "{txid}",);

    for (i, expected) in expected_outputs.iter().enumerate() {
      let output = &payload.credit_outputs[i];

      assert_eq!(
        output.value,
        bitcoin_units::Amount::from_sat(util::json_u64(&expected["valueSat"])).unwrap(),
        "{txid} output {i}",
      );

      let expected_script = Vec::<u8>::from_hex(util::json_str(&expected["scriptPubKey"])).unwrap();
      assert_eq!(
        output.script_pubkey.as_bytes(),
        &expected_script[..],
        "{txid} output {i} script",
      );
    }
  }
}

#[rstest]
fn round_trip() {
  let corpus = util::load_transactions("assetlock");
  for (txid, entry) in &corpus {
    let tx = util::decode_tx(&entry.raw);
    util::assert_round_trip(&entry.raw, &tx, txid);
  }
}
