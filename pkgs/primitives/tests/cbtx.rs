//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! KAT tests for CoinbaseCommitment coinbase commitment payload.

#![expect(clippy::unwrap_used, reason = "test code")]

mod util;

use dash_primitives::payload::CoinbaseCommitment;
use dash_primitives::MerkleRoot;
use dash_types::BlsSignatureBytes;
use hex_conservative::FromHex;
use rstest::rstest;

#[rstest]
fn decode_fields() {
  let corpus = util::load_transactions("cbtx");
  for (txid, entry) in &corpus {
    util::assert_txid(&entry.raw, txid);
    let tx = util::decode_tx(&entry.raw);
    assert!(tx.validate(&Default::default()).is_ok());
    assert!(!tx.extra_payload.is_empty(), "{txid}");

    let cbtx = CoinbaseCommitment::decode(&mut &tx.extra_payload[..]).unwrap();
    assert!(cbtx.validate(&Default::default()).is_ok());
    let d = &entry.details;

    assert_eq!(cbtx.version, util::json_u64(&d["version"]) as u16, "{txid}",);
    assert_eq!(
      cbtx.height,
      bitcoin_units::BlockHeight::from_u32(util::json_u64(&d["height"]) as u32),
      "{txid}",
    );
    assert_eq!(
      cbtx.merkle_root_mn_list,
      MerkleRoot::from_hex(util::json_str(&d["merkleRootMNList"])).unwrap(),
      "{txid}",
    );

    if let Some(mrq) = d.get("merkleRootQuorums") {
      assert_eq!(
        cbtx.merkle_root_quorums.unwrap(),
        MerkleRoot::from_hex(util::json_str(mrq)).unwrap(),
        "{txid}",
      );
    }

    if let Some(diff) = d.get("bestCLHeightDiff") {
      assert_eq!(cbtx.best_cl_height_diff.unwrap(), util::json_u64(diff), "{txid}",);
    }

    if let Some(sig) = d.get("bestCLSignature") {
      let expected: [u8; 96] = Vec::<u8>::from_hex(util::json_str(sig)).unwrap().try_into().unwrap();
      assert_eq!(cbtx.best_cl_signature.unwrap(), BlsSignatureBytes(expected), "{txid}",);
    }

    if let Some(bal) = d.get("creditPoolBalance") {
      let bal_f = bal.as_f64().unwrap();
      assert_eq!(cbtx.credit_pool_balance.unwrap(), util::duffs(bal_f), "{txid}",);
    }
  }
}

#[rstest]
fn round_trip() {
  let corpus = util::load_transactions("cbtx");
  for (txid, entry) in &corpus {
    let tx = util::decode_tx(&entry.raw);
    util::assert_round_trip(&entry.raw, &tx, txid);
  }
}
