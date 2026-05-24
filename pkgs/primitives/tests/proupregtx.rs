//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! KAT tests for ProUpRegTx registrar-update payload.

#![expect(clippy::unwrap_used, reason = "test code")]

mod util;

use dash_primitives::payload::ProUpRegTx;
use dash_primitives::{InputsHash, TxHash};
use dash_script::KeyId;
use dash_types::BlsPublicKeyBytes;
use hex_conservative::FromHex;
use rstest::rstest;

#[rstest]
fn decode_fields() {
  let corpus = util::load_transactions("proupregtx");
  for (txid, entry) in &corpus {
    util::assert_txid(&entry.raw, txid);
    let tx = util::decode_tx(&entry.raw);
    assert!(tx.validate(&Default::default()).is_ok());
    assert!(!tx.extra_payload.is_empty(), "{txid}");

    let payload = ProUpRegTx::decode(&mut &tx.extra_payload[..]).unwrap();
    assert!(payload.validate(&Default::default()).is_ok());
    let d = &entry.details;

    assert_eq!(payload.version, util::json_u64(&d["version"]) as u16, "{txid}",);
    assert_eq!(
      payload.pro_tx_hash,
      TxHash::from_hex(util::json_str(&d["proTxHash"])).unwrap(),
      "{txid} proTxHash",
    );

    if let Some(voting) = d.get("votingAddress") {
      let key_id = util::decode_address_key_id(util::json_str(voting));
      assert_eq!(payload.key_id_voting, KeyId(key_id), "{txid} votingAddress",);
    }

    let expected_pubkey: [u8; 48] = Vec::<u8>::from_hex(util::json_str(&d["pubKeyOperator"]))
      .unwrap()
      .try_into()
      .unwrap();
    assert_eq!(
      payload.pub_key_operator,
      BlsPublicKeyBytes(expected_pubkey),
      "{txid} pubKeyOperator",
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
  let corpus = util::load_transactions("proupregtx");
  for (txid, entry) in &corpus {
    let tx = util::decode_tx(&entry.raw);
    util::assert_round_trip(&entry.raw, &tx, txid);
  }
}
