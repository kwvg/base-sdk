//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! KAT tests for MnHardFork hard-fork signal.

#![expect(clippy::unwrap_used, reason = "test code")]

mod util;

use dash_primitives::payload::MnHardFork;
use dash_primitives::QuorumHash;
use dash_types::BlsSignatureBytes;
use hex_conservative::FromHex;
use rstest::rstest;

#[rstest]
fn decode_fields() {
  let corpus = util::load_transactions("mnhftx");
  for (txid, entry) in &corpus {
    util::assert_txid(&entry.raw, txid);
    let tx = util::decode_tx(&entry.raw);
    assert!(tx.validate(&Default::default()).is_ok());
    assert!(!tx.extra_payload.is_empty(), "{txid}");

    let payload = MnHardFork::decode(&mut &tx.extra_payload[..]).unwrap();
    assert!(payload.validate(&Default::default()).is_ok());
    let d = &entry.details;
    let signal = &d["signal"];

    assert_eq!(payload.version, util::json_u64(&d["version"]) as u8, "{txid}",);
    assert_eq!(
      payload.version_bit,
      util::json_u64(&signal["versionBit"]) as u8,
      "{txid}",
    );
    assert_eq!(
      payload.quorum_hash,
      QuorumHash::from_hex(util::json_str(&signal["quorumHash"])).unwrap(),
      "{txid}",
    );

    let expected_sig: [u8; 96] = Vec::<u8>::from_hex(util::json_str(&signal["sig"]))
      .unwrap()
      .try_into()
      .unwrap();
    assert_eq!(payload.sig, BlsSignatureBytes(expected_sig), "{txid}",);
  }
}

#[rstest]
fn round_trip() {
  let corpus = util::load_transactions("mnhftx");
  for (txid, entry) in &corpus {
    let tx = util::decode_tx(&entry.raw);
    util::assert_round_trip(&entry.raw, &tx, txid);
  }
}
