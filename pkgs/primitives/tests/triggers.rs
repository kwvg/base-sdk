//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! KAT tests for governance trigger (superblock) objects.

#![expect(clippy::unwrap_used, reason = "test code")]

mod util;

use dash_primitives::gov::{GovObject, GovObjectType};
use dash_primitives::TxHash;
use hex_conservative::FromHex;
use rstest::rstest;

#[rstest]
fn decode_and_hash() {
  let corpus = util::load_triggers();
  for (obj_hash_hex, entry) in &corpus {
    let raw = Vec::<u8>::from_hex(&entry.raw).unwrap();
    let obj = GovObject::decode(&mut &raw[..]).unwrap();
    let d = &entry.details;
    let payload = &d["payload"];

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
      obj.object_type,
      GovObjectType::from_i32(util::json_u64(&d["object_type"]) as i32),
      "{obj_hash_hex} object_type",
    );

    // Verify the JSON data payload parses correctly.
    let json_str = obj.data_as_string().unwrap();
    let parsed: serde_json::Value = serde_json::from_str(json_str).unwrap();
    assert_eq!(
      parsed["event_block_height"].as_i64().unwrap(),
      payload["event_block_height"].as_i64().unwrap(),
      "{obj_hash_hex} event_block_height",
    );
    assert_eq!(
      parsed["payment_addresses"].as_str().unwrap(),
      util::json_str(&payload["payment_addresses"]),
      "{obj_hash_hex} payment_addresses",
    );
    assert_eq!(
      parsed["payment_amounts"].as_str().unwrap(),
      util::json_str(&payload["payment_amounts"]),
      "{obj_hash_hex} payment_amounts",
    );
    assert_eq!(
      parsed["proposal_hashes"].as_str().unwrap(),
      util::json_str(&payload["proposal_hashes"]),
      "{obj_hash_hex} proposal_hashes",
    );

    // The corpus key IS the canonical governance hash.
    let computed_hash = obj.hash();
    let expected_hash = TxHash::from_hex(obj_hash_hex).unwrap();
    assert_eq!(computed_hash, expected_hash, "{obj_hash_hex} governance hash");
  }
}
