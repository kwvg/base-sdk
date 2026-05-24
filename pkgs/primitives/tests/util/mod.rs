//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Shared test utilities for corpus-driven KAT tests.

#![allow(dead_code)]

use bitcoin_consensus_encoding::{decode_from_slice, encode_to_vec};
use dash_primitives::{Transaction, TxHash};
use hex_conservative::FromHex;
use serde::Deserialize;

use std::collections::BTreeMap;

/// A single entry from a transaction corpus JSON5 file.
#[derive(Debug, Deserialize)]
pub struct CorpusTx {
  pub raw: String,
  pub details: serde_json::Value,
}

/// Loads a corpus file and returns txid -> entry map.
///
/// The JSON5 file has shape `{ "<type>": { "<txid>": { raw, details } } }`.
pub fn load_transactions(name: &str) -> BTreeMap<String, CorpusTx> {
  let path = format!("{}/corpus/{}.json5", env!("CARGO_MANIFEST_DIR"), name,);
  let text = std::fs::read_to_string(&path).unwrap();
  let outer: BTreeMap<String, BTreeMap<String, CorpusTx>> = json5::from_str(&text).unwrap();
  outer.into_values().next().unwrap()
}

/// A single entry from the block corpus JSON5 file.
#[derive(Debug, Deserialize)]
pub struct CorpusBlock {
  pub raw: String,
  pub header: serde_json::Value,
  pub body: serde_json::Value,
}

/// Loads the block corpus file.
pub fn load_blocks() -> BTreeMap<String, CorpusBlock> {
  let path = format!("{}/corpus/blocks.json5", env!("CARGO_MANIFEST_DIR"),);
  let text = std::fs::read_to_string(&path).unwrap();
  let outer: BTreeMap<String, BTreeMap<String, CorpusBlock>> = json5::from_str(&text).unwrap();
  outer.into_values().next().unwrap()
}

/// A single entry from the proposal corpus JSON5 file.
#[derive(Debug, Deserialize)]
pub struct CorpusProposal {
  pub raw: String,
  pub details: serde_json::Value,
}

/// Loads the proposal corpus file.
pub fn load_proposals() -> BTreeMap<String, CorpusProposal> {
  let path = format!("{}/corpus/proposals.json5", env!("CARGO_MANIFEST_DIR"),);
  let text = std::fs::read_to_string(&path).unwrap();
  let outer: BTreeMap<String, BTreeMap<String, CorpusProposal>> = json5::from_str(&text).unwrap();
  outer.into_values().next().unwrap()
}

/// A single entry from the trigger corpus JSON5 file.
#[derive(Debug, Deserialize)]
pub struct CorpusTrigger {
  pub raw: String,
  pub details: serde_json::Value,
}

/// Loads the trigger corpus file.
pub fn load_triggers() -> BTreeMap<String, CorpusTrigger> {
  let path = format!("{}/corpus/triggers.json5", env!("CARGO_MANIFEST_DIR"),);
  let text = std::fs::read_to_string(&path).unwrap();
  let outer: BTreeMap<String, BTreeMap<String, CorpusTrigger>> = json5::from_str(&text).unwrap();
  outer.into_values().next().unwrap()
}

/// Decodes a raw transaction hex string into a `Transaction`.
pub fn decode_tx(raw_hex: &str) -> Transaction {
  let bytes = Vec::<u8>::from_hex(raw_hex).unwrap();
  decode_from_slice::<Transaction>(&bytes).unwrap()
}

/// Asserts that re-encoding a transaction produces the same bytes.
pub fn assert_round_trip(raw_hex: &str, tx: &Transaction, label: &str) {
  let expected = Vec::<u8>::from_hex(raw_hex).unwrap();
  let encoded = encode_to_vec(tx);
  assert_eq!(encoded, expected, "round-trip mismatch for {label}");
}

/// Asserts that `double_sha256(raw_hex)` matches the corpus txid key.
pub fn assert_txid(raw_hex: &str, expected_txid: &str) {
  let raw = Vec::<u8>::from_hex(raw_hex).unwrap();
  let computed = dash_primitives::hash::tx_hash(&raw);
  let expected = TxHash::from_hex(expected_txid).unwrap();
  assert_eq!(computed, expected, "txid mismatch for {expected_txid}");
}

/// Parses a display-order hex string into a reversed byte array.
///
/// Dash Core RPC shows 20-byte identifiers (like `platformNodeID`)
/// in big-endian display order; this reverses them to wire order.
/// For 32-byte hashes, use `Hash256::from_hex()` instead.
pub fn parse_reversed_hex<const N: usize>(hex_str: &str) -> [u8; N] {
  let decoded = Vec::<u8>::from_hex(hex_str).unwrap();
  assert_eq!(decoded.len(), N, "expected {N}-byte value, got {}", decoded.len());
  let mut bytes = [0u8; N];
  bytes.copy_from_slice(&decoded);
  bytes.reverse();
  bytes
}

/// Converts a DASH amount (f64) to duffs (i64).
pub fn duffs(dash: f64) -> i64 {
  (dash * 100_000_000.0).round() as i64
}

/// Decodes a Base58Check address and returns the 20-byte hash (KeyId).
pub fn decode_address_key_id(addr: &str) -> [u8; 20] {
  let payload = base58ck::decode_check(addr).unwrap();
  let mut key_id = [0u8; 20];
  key_id.copy_from_slice(&payload[1..21]);
  key_id
}

/// Extracts a `u64` from a JSON value.
pub fn json_u64(v: &serde_json::Value) -> u64 {
  v.as_u64().unwrap()
}

/// Extracts a `str` from a JSON value.
pub fn json_str(v: &serde_json::Value) -> &str {
  v.as_str().unwrap()
}
