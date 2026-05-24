//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! KAT tests for AssetUnlock.

#![expect(clippy::unwrap_used, reason = "test code")]

mod util;

use dash_primitives::payload::AssetUnlock;
use dash_primitives::QuorumHash;
use dash_types::BlsSignatureBytes;
use hex_conservative::FromHex;
use rstest::rstest;

#[rstest]
fn decode_fields() {
  let corpus = util::load_transactions("assetunlock");
  for (txid, entry) in &corpus {
    util::assert_txid(&entry.raw, txid);
    let tx = util::decode_tx(&entry.raw);
    assert!(tx.validate(&Default::default()).is_ok());
    assert!(!tx.extra_payload.is_empty(), "{txid}");

    let payload = AssetUnlock::decode(&mut &tx.extra_payload[..]).unwrap();
    assert!(payload.validate(&Default::default()).is_ok());
    let d = &entry.details;

    assert_eq!(payload.version, util::json_u64(&d["version"]) as u8, "{txid}",);
    assert_eq!(payload.index, util::json_u64(&d["index"]), "{txid}",);
    assert_eq!(payload.fee, util::json_u64(&d["fee"]) as u32, "{txid}",);
    assert_eq!(
      payload.requested_height,
      util::json_u64(&d["requestedHeight"]) as u32,
      "{txid}",
    );
    assert_eq!(
      payload.quorum_hash,
      QuorumHash::from_hex(util::json_str(&d["quorumHash"])).unwrap(),
      "{txid}",
    );

    let expected_sig: [u8; 96] = Vec::<u8>::from_hex(util::json_str(&d["quorumSig"]))
      .unwrap()
      .try_into()
      .unwrap();
    assert_eq!(payload.quorum_sig, BlsSignatureBytes(expected_sig), "{txid}",);
  }
}

#[rstest]
fn round_trip() {
  let corpus = util::load_transactions("assetunlock");
  for (txid, entry) in &corpus {
    let tx = util::decode_tx(&entry.raw);
    util::assert_round_trip(&entry.raw, &tx, txid);
  }
}
