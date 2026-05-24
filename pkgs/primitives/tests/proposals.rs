//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! KAT tests for governance proposal objects.

#![expect(clippy::unwrap_used, reason = "test code")]

mod util;

use dash_primitives::gov::{GovObject, GovObjectType, Proposal};
use dash_primitives::TxHash;
use hex_conservative::FromHex;
use rstest::rstest;

#[rstest]
fn decode_and_hash() {
  let corpus = util::load_proposals();
  for (obj_hash_hex, entry) in &corpus {
    let raw = Vec::<u8>::from_hex(&entry.raw).unwrap();
    let obj = GovObject::decode(&mut &raw[..]).unwrap();
    let d = &entry.details;
    let payload = &d["payload"];

    // Verify decoded fields match corpus metadata.
    assert_eq!(
      obj.hash_parent,
      TxHash::from_hex(util::json_str(&d["hash_parent"])).unwrap(),
      "{obj_hash_hex} hash_parent",
    );
    assert_eq!(
      obj.revision,
      util::json_u64(&d["revision"]) as i32,
      "{obj_hash_hex} revision"
    );
    assert_eq!(obj.time, d["creation_time"].as_i64().unwrap(), "{obj_hash_hex} time");
    assert_eq!(
      obj.collateral_hash,
      TxHash::from_hex(util::json_str(&d["collateral_hash"])).unwrap(),
      "{obj_hash_hex} collateral_hash",
    );
    assert_eq!(
      obj.object_type,
      GovObjectType::from_i32(util::json_u64(&d["object_type"]) as i32),
      "{obj_hash_hex} object_type",
    );

    // Verify the JSON data payload parses correctly.
    let json_str = obj.data_as_string().unwrap();
    let parsed: serde_json::Value = serde_json::from_str(json_str).unwrap();
    assert_eq!(
      parsed["name"].as_str().unwrap(),
      util::json_str(&payload["name"]),
      "{obj_hash_hex} name"
    );
    assert_eq!(
      parsed["url"].as_str().unwrap(),
      util::json_str(&payload["url"]),
      "{obj_hash_hex} url"
    );
    assert_eq!(
      parsed["payment_address"].as_str().unwrap(),
      util::json_str(&payload["payment_address"]),
      "{obj_hash_hex} payment_address",
    );
    assert_eq!(
      parsed["start_epoch"].as_i64().unwrap(),
      payload["start_epoch"].as_i64().unwrap(),
      "{obj_hash_hex} start_epoch",
    );
    assert_eq!(
      parsed["end_epoch"].as_i64().unwrap(),
      payload["end_epoch"].as_i64().unwrap(),
      "{obj_hash_hex} end_epoch",
    );

    // Validate the proposal fields.
    let proposal = Proposal {
      name: parsed["name"].as_str().unwrap().into(),
      url: parsed["url"].as_str().unwrap().into(),
      payment_address: parsed["payment_address"].as_str().unwrap().into(),
      payment_amount: parsed["payment_amount"].to_string(),
      start_epoch: parsed["start_epoch"].as_i64().unwrap(),
      end_epoch: parsed["end_epoch"].as_i64().unwrap(),
    };
    assert!(proposal.validate().is_ok());

    // The corpus key IS the canonical governance hash.
    let computed_hash = obj.hash();
    let expected_hash = TxHash::from_hex(obj_hash_hex).unwrap();
    assert_eq!(computed_hash, expected_hash, "{obj_hash_hex} governance hash");
  }
}
