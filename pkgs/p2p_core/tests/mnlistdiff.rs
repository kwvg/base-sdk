//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! KAT tests for MnListDiffPayload.

#![expect(clippy::unwrap_used, reason = "test code")]

use bitcoin_consensus_encoding::{decode_from_slice, encode_to_vec};
use dash_p2p_core::primitives::mn_list::MnListDiffPayload;
use hex_conservative::FromHex;
use rstest::rstest;
use serde::Deserialize;

use std::collections::BTreeMap;

/// A single entry from the mnlistdiff corpus.
#[derive(Debug, Deserialize)]
struct CorpusEntry {
  raw: String,
  details: MnListDiffPayload,
}

/// Loads the mnlistdiff corpus file.
fn load_corpus() -> BTreeMap<String, CorpusEntry> {
  let path = format!("{}/corpus/mnlistdiff.json5", env!("CARGO_MANIFEST_DIR"));
  let text = std::fs::read_to_string(&path).unwrap();
  let outer: BTreeMap<String, BTreeMap<String, CorpusEntry>> = json5::from_str(&text).unwrap();
  outer.into_values().next().unwrap()
}

#[rstest]
fn decode_fields() {
  let corpus = load_corpus();
  for (block_hash, entry) in &corpus {
    let bytes = Vec::<u8>::from_hex(&entry.raw).unwrap();
    let decoded: MnListDiffPayload = decode_from_slice(&bytes).unwrap();

    assert_eq!(decoded.block_hash.to_string(), *block_hash, "block_hash key mismatch");
    assert_eq!(
      decoded, entry.details,
      "decoded payload != corpus details for {block_hash}"
    );
  }
}

#[rstest]
fn round_trip() {
  let corpus = load_corpus();
  for (block_hash, entry) in &corpus {
    let bytes = Vec::<u8>::from_hex(&entry.raw).unwrap();
    let decoded: MnListDiffPayload = decode_from_slice(&bytes).unwrap();
    let encoded = encode_to_vec(&decoded);
    assert_eq!(encoded, bytes, "round-trip mismatch for {block_hash}");
  }
}
