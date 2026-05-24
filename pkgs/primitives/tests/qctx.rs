//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! KAT tests for FinalCommitment (LLMQ commitment).

#![expect(clippy::unwrap_used, reason = "test code")]

mod util;

use dash_primitives::payload::FinalCommitment;
use dash_primitives::{LlmqType, QuorumHash, QuorumVvecHash};
use dash_types::codec::NumCodec;
use dash_types::{BlsPublicKeyBytes, BlsSignatureBytes};
use hex_conservative::FromHex;
use rstest::rstest;

#[rstest]
fn decode_fields() {
  let corpus = util::load_transactions("qctx");
  for (txid, entry) in &corpus {
    util::assert_txid(&entry.raw, txid);
    let tx = util::decode_tx(&entry.raw);
    assert!(tx.validate(&Default::default()).is_ok());
    assert!(!tx.extra_payload.is_empty(), "{txid}");

    let payload = FinalCommitment::decode(&mut &tx.extra_payload[..]).unwrap();
    let d = &entry.details;

    assert_eq!(payload.version, util::json_u64(&d["version"]) as u16, "{txid} version",);
    assert_eq!(
      payload.height,
      bitcoin_units::BlockHeight::from_u32(util::json_u64(&d["height"]) as u32),
      "{txid} height",
    );

    let c = &d["commitment"];
    let commitment = &payload.commitment;

    assert_eq!(
      commitment.version,
      util::json_u64(&c["version"]) as u16,
      "{txid} commitment.version",
    );
    assert_eq!(
      commitment.llmq_type,
      LlmqType::from_base(util::json_u64(&c["llmqType"]) as u8),
      "{txid} commitment.llmqType",
    );
    assert_eq!(
      commitment.quorum_hash,
      QuorumHash::from_hex(util::json_str(&c["quorumHash"])).unwrap(),
      "{txid} commitment.quorumHash",
    );

    if let Some(qi) = commitment.quorum_index {
      assert_eq!(
        qi,
        util::json_u64(&c["quorumIndex"]) as i16,
        "{txid} commitment.quorumIndex",
      );
    }

    assert_eq!(
      commitment.signers.count_ones(),
      util::json_u64(&c["signersCount"]),
      "{txid} commitment.signersCount",
    );
    assert_eq!(
      commitment.valid_members.count_ones(),
      util::json_u64(&c["validMembersCount"]),
      "{txid} commitment.validMembersCount",
    );

    // Bitset raw data
    let expected_signers = Vec::<u8>::from_hex(util::json_str(&c["signers"])).unwrap();
    assert_eq!(commitment.signers.data, expected_signers, "{txid} commitment.signers",);
    let expected_valid = Vec::<u8>::from_hex(util::json_str(&c["validMembers"])).unwrap();
    assert_eq!(
      commitment.valid_members.data, expected_valid,
      "{txid} commitment.validMembers",
    );

    let expected_pk: [u8; 48] = Vec::<u8>::from_hex(util::json_str(&c["quorumPublicKey"]))
      .unwrap()
      .try_into()
      .unwrap();
    assert_eq!(
      commitment.quorum_public_key,
      BlsPublicKeyBytes(expected_pk),
      "{txid} commitment.quorumPublicKey",
    );

    assert_eq!(
      commitment.quorum_vvec_hash,
      QuorumVvecHash::from_hex(util::json_str(&c["quorumVvecHash"])).unwrap(),
      "{txid} commitment.quorumVvecHash",
    );

    let expected_qsig: [u8; 96] = Vec::<u8>::from_hex(util::json_str(&c["quorumSig"]))
      .unwrap()
      .try_into()
      .unwrap();
    assert_eq!(
      commitment.quorum_sig,
      BlsSignatureBytes(expected_qsig),
      "{txid} commitment.quorumSig",
    );

    let expected_msig: [u8; 96] = Vec::<u8>::from_hex(util::json_str(&c["membersSig"]))
      .unwrap()
      .try_into()
      .unwrap();
    assert_eq!(
      commitment.members_sig,
      BlsSignatureBytes(expected_msig),
      "{txid} commitment.membersSig",
    );
  }
}

#[rstest]
fn round_trip() {
  let corpus = util::load_transactions("qctx");
  for (txid, entry) in &corpus {
    let tx = util::decode_tx(&entry.raw);
    util::assert_round_trip(&entry.raw, &tx, txid);
  }
}
