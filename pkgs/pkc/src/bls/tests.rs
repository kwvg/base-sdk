//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Shared test constants and corpus helpers for BLS modules.

use alloc::{format, vec::Vec};
use hex_literal::hex;

pub(super) type VectorFile = serde_json::Value;

pub(super) const SEED_0: [u8; 32] = [0u8; 32];
pub(super) const SEED_1: [u8; 32] = [1u8; 32];

pub(super) const MSG_DEADBEEF: [u8; 32] = hex!(
  "deadbeefdeadbeefdeadbeefdeadbeef"
  "cafebabecafebabecafebabecafebabe"
);

pub(super) fn load(name: &str) -> VectorFile {
  let path = format!("{}/corpus/{}.json", env!("CARGO_MANIFEST_DIR"), name);
  let data = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("cannot read {path}: {e}"));
  serde_json::from_str(&data).unwrap_or_else(|e| panic!("cannot parse {path}: {e}"))
}

pub(super) fn parse_sub<T: serde::de::DeserializeOwned>(file: &VectorFile, key: &str) -> Vec<T> {
  let arr = file
    .get(key)
    .unwrap_or_else(|| panic!("missing key '{key}' in vector file"));
  serde_json::from_value(arr.clone()).unwrap_or_else(|e| panic!("cannot parse '{key}': {e}"))
}

pub(super) fn decode_hex(s: &str) -> Vec<u8> {
  (0..s.len())
    .step_by(2)
    .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
    .collect()
}

pub(super) fn hex_to_32(s: &str) -> [u8; 32] {
  decode_hex(s).try_into().unwrap()
}

pub(super) fn hex_to_48(s: &str) -> [u8; 48] {
  decode_hex(s).try_into().unwrap()
}

pub(super) fn hash_from_hex(s: &str) -> dash_num::Hash256 {
  dash_num::Hash256::from_hex(s).unwrap()
}

pub(super) fn make_id(i: u32) -> dash_num::Hash256 {
  let mut bytes = [0u8; 32];
  bytes[28..32].copy_from_slice(&i.to_be_bytes());
  dash_num::Hash256::from_bytes(bytes)
}

pub(super) fn sequential_ids(n: usize) -> Vec<dash_num::Hash256> {
  (1..=n).map(|i| make_id(i as u32)).collect()
}
