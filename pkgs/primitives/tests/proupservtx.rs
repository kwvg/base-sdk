//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! KAT tests for ProUpServTx service-update payload.

#![expect(clippy::unwrap_used, reason = "test code")]

mod util;

use dash_primitives::payload::ProUpServTx;
use dash_primitives::{InputsHash, TxHash};
use rstest::rstest;

#[rstest]
fn decode_fields() {
  let corpus = util::load_transactions("proupservtx");
  for (txid, entry) in &corpus {
    util::assert_txid(&entry.raw, txid);
    let tx = util::decode_tx(&entry.raw);
    assert!(tx.validate(&Default::default()).is_ok());
    assert!(!tx.extra_payload.is_empty(), "{txid}");

    let payload = ProUpServTx::decode(&mut &tx.extra_payload[..]).unwrap();
    assert!(payload.validate(&Default::default()).is_ok());
    let d = &entry.details;

    assert_eq!(payload.version, util::json_u64(&d["version"]) as u16, "{txid}",);
    assert_eq!(
      payload.pro_tx_hash,
      TxHash::from_hex(util::json_str(&d["proTxHash"])).unwrap(),
      "{txid} proTxHash",
    );
    assert_eq!(
      payload.inputs_hash,
      InputsHash::from_hex(util::json_str(&d["inputsHash"])).unwrap(),
      "{txid} inputsHash",
    );
  }
}

#[rstest]
fn round_trip() {
  let corpus = util::load_transactions("proupservtx");
  for (txid, entry) in &corpus {
    let tx = util::decode_tx(&entry.raw);
    util::assert_round_trip(&entry.raw, &tx, txid);
  }
}
