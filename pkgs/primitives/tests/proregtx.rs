//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! KAT tests for ProRegTx registration payload.

#![expect(clippy::unwrap_used, reason = "test code")]

mod util;

use dash_primitives::payload::ProRegTx;
use dash_primitives::{InputsHash, TxHash};
use dash_script::KeyId;
use dash_types::{BlsPublicKeyBytes, PlatformNodeId};
use hex_conservative::FromHex;
use rstest::rstest;

#[rstest]
fn decode_fields() {
  let corpus = util::load_transactions("proregtx");
  for (txid, entry) in &corpus {
    util::assert_txid(&entry.raw, txid);
    let tx = util::decode_tx(&entry.raw);
    assert!(tx.validate(&Default::default()).is_ok());
    assert!(!tx.extra_payload.is_empty(), "{txid}");

    let payload = ProRegTx::decode(&mut &tx.extra_payload[..]).unwrap();
    assert!(payload.validate(&Default::default()).is_ok());
    let d = &entry.details;

    assert_eq!(payload.version, util::json_u64(&d["version"]) as u16, "{txid}",);

    assert_eq!(
      payload.collateral_hash,
      TxHash::from_hex(util::json_str(&d["collateralHash"])).unwrap(),
      "{txid} collateralHash",
    );
    assert_eq!(
      payload.collateral_index,
      util::json_u64(&d["collateralIndex"]) as u32,
      "{txid} collateralIndex",
    );

    // Owner address -> KeyId via Base58Check
    if let Some(owner) = d.get("ownerAddress") {
      let key_id = util::decode_address_key_id(util::json_str(owner));
      assert_eq!(payload.key_id_owner, KeyId(key_id), "{txid} ownerAddress",);
    }

    // Voting address -> KeyId via Base58Check
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
      payload.operator_reward,
      util::json_u64(&d["operatorReward"]) as u16,
      "{txid} operatorReward",
    );

    assert_eq!(
      payload.inputs_hash,
      InputsHash::from_hex(util::json_str(&d["inputsHash"])).unwrap(),
      "{txid} inputsHash",
    );

    // Platform fields (Evo masternodes)
    if let Some(node_id) = d.get("platformNodeID") {
      assert_eq!(
        payload.platform_node_id.unwrap(),
        PlatformNodeId(util::parse_reversed_hex::<20>(util::json_str(node_id))),
        "{txid} platformNodeID",
      );
    }

    if let Some(p2p) = d.get("platformP2PPort") {
      assert_eq!(
        payload.platform_p2p_port.unwrap(),
        util::json_u64(p2p) as u16,
        "{txid} platformP2PPort",
      );
    }

    if let Some(http) = d.get("platformHTTPPort") {
      assert_eq!(
        payload.platform_http_port.unwrap(),
        util::json_u64(http) as u16,
        "{txid} platformHTTPPort",
      );
    }
  }
}

#[rstest]
fn round_trip() {
  let corpus = util::load_transactions("proregtx");
  for (txid, entry) in &corpus {
    let tx = util::decode_tx(&entry.raw);
    util::assert_round_trip(&entry.raw, &tx, txid);
  }
}
