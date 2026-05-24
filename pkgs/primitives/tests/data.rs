//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! KAT tests for data (OP_RETURN) transactions.

#![expect(clippy::unwrap_used, reason = "test code")]

mod util;

use dash_primitives::{TxHash, TxType};
use dash_types::codec::NumCodec;
use hex_conservative::FromHex;
use rstest::rstest;

#[rstest]
fn decode_fields() {
  let corpus = util::load_transactions("data");
  for (txid, entry) in &corpus {
    util::assert_txid(&entry.raw, txid);
    let tx = util::decode_tx(&entry.raw);
    assert!(tx.validate(&Default::default()).is_ok());
    let d = &entry.details;

    assert_eq!(tx.version, util::json_u64(&d["version"]) as i16, "{txid} version",);
    assert_eq!(
      tx.tx_type,
      TxType::from_base(util::json_u64(&d["type"]) as u16),
      "{txid} type",
    );
    assert_eq!(tx.lock_time, util::json_u64(&d["locktime"]) as u32, "{txid} locktime",);

    let expected_vin = d["vin"].as_array().unwrap();
    assert_eq!(tx.inputs.len(), expected_vin.len(), "{txid} input count",);

    for (i, ev) in expected_vin.iter().enumerate() {
      if let Some(cb) = ev.get("coinbase") {
        // Coinbase input
        let expected_script = Vec::<u8>::from_hex(util::json_str(cb)).unwrap();
        assert_eq!(
          tx.inputs[i].script_sig.as_bytes(),
          &expected_script[..],
          "{txid} vin[{i}] coinbase",
        );
      } else {
        // Regular input
        assert_eq!(
          tx.inputs[i].prevout.hash,
          TxHash::from_hex(util::json_str(&ev["txid"])).unwrap(),
          "{txid} vin[{i}] txid",
        );
        assert_eq!(
          tx.inputs[i].prevout.index,
          util::json_u64(&ev["vout"]) as u32,
          "{txid} vin[{i}] vout",
        );
      }
      assert_eq!(
        tx.inputs[i].sequence,
        util::json_u64(&ev["sequence"]) as u32,
        "{txid} vin[{i}] sequence",
      );
    }

    let expected_vout = d["vout"].as_array().unwrap();
    assert_eq!(tx.outputs.len(), expected_vout.len(), "{txid} output count",);

    for (i, ev) in expected_vout.iter().enumerate() {
      assert_eq!(
        tx.outputs[i].value,
        bitcoin_units::Amount::from_sat(util::json_u64(&ev["valueSat"])).unwrap(),
        "{txid} vout[{i}] value",
      );
      let expected_script = Vec::<u8>::from_hex(util::json_str(&ev["scriptPubKey"])).unwrap();
      assert_eq!(
        tx.outputs[i].script_pubkey.as_bytes(),
        &expected_script[..],
        "{txid} vout[{i}] scriptPubKey",
      );
    }
  }
}

#[rstest]
fn round_trip() {
  let corpus = util::load_transactions("data");
  for (txid, entry) in &corpus {
    let tx = util::decode_tx(&entry.raw);
    util::assert_round_trip(&entry.raw, &tx, txid);
  }
}
