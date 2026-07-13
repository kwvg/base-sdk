//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Shared test and benchmark fixtures and corpus helpers.

#![allow(dead_code, reason = "fixtures are used according to enabled algorithms")]

use alloc::format;
use alloc::vec::Vec;
use hex_literal::hex;

pub type VectorFile = serde_json::Value;

pub const SEED_0: [u8; 32] = [0u8; 32];
pub const SEED_1: [u8; 32] = [1u8; 32];

pub const MSG_DEADBEEF: [u8; 32] = hex!(
  "deadbeefdeadbeefdeadbeefdeadbeef"
  "cafebabecafebabecafebabecafebabe"
);

pub fn load(name: &str) -> VectorFile {
  let path = format!("{}/corpus/{}.json", env!("CARGO_MANIFEST_DIR"), name);
  let data = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("cannot read {path}: {e}"));
  serde_json::from_str(&data).unwrap_or_else(|e| panic!("cannot parse {path}: {e}"))
}

pub fn parse_sub<T: serde::de::DeserializeOwned>(file: &VectorFile, key: &str) -> Vec<T> {
  let arr = file
    .get(key)
    .unwrap_or_else(|| panic!("missing key '{key}' in vector file"));
  serde_json::from_value(arr.clone()).unwrap_or_else(|e| panic!("cannot parse '{key}': {e}"))
}

pub fn decode_hex(s: &str) -> Vec<u8> {
  (0..s.len())
    .step_by(2)
    .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
    .collect()
}

pub fn hex_to_32(s: &str) -> [u8; 32] {
  decode_hex(s).try_into().unwrap()
}

pub fn hex_to_48(s: &str) -> [u8; 48] {
  decode_hex(s).try_into().unwrap()
}

pub fn hash_from_hex(s: &str) -> dash_num::Hash256 {
  dash_num::Hash256::from_hex(s).unwrap()
}

pub fn test_ikm(i: u8) -> [u8; 32] {
  let mut ikm = [0u8; 32];
  ikm[0] = i;
  ikm[31] = i.wrapping_add(1);
  ikm
}

pub fn test_msg(i: u8) -> [u8; 32] {
  let mut msg = [0u8; 32];
  msg[0] = i.wrapping_mul(7);
  msg[15] = i;
  msg
}

pub fn make_id(i: u32) -> dash_num::Hash256 {
  let mut bytes = [0u8; 32];
  bytes[28..32].copy_from_slice(&i.to_be_bytes());
  dash_num::Hash256::from_bytes(bytes)
}

pub fn sequential_ids(n: usize) -> Vec<dash_num::Hash256> {
  (1..=n).map(|i| make_id(i as u32)).collect()
}
