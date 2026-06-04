//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Shared NIST KAT helpers.

#![allow(dead_code)]
#![expect(clippy::expect_used, reason = "test code")]

use hex_conservative::FromHex;

use std::collections::HashMap;

const NIST_MSG_BLOB: &[u8] = include_bytes!("../../corpus/nist_msg.bin");

/// Returns the NIST test message of `byte_len` bytes.
///
/// The message blob contains messages of length 0..=255 bytes, laid out at
/// triangular offsets so each message is uniquely determined by its length.
pub fn nist_input(byte_len: usize) -> &'static [u8] {
  assert!(byte_len <= 255, "byte_len must be <= 255");
  let off = byte_len.wrapping_mul(byte_len.wrapping_sub(1)) / 2;
  &NIST_MSG_BLOB[off..off + byte_len]
}

/// Expected 64-byte digest, parsed from a JSON5 file.
pub type NistVectors = HashMap<usize, [u8; 64]>;

/// Loads a corpus file by name and returns the parsed vectors.
pub fn load(name: &str) -> NistVectors {
  let path = format!("{}/corpus/{}.json", env!("CARGO_MANIFEST_DIR"), name,);
  let data = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("cannot read {path}: {e}"));
  let raw: HashMap<String, String> = serde_json::from_str(&data).unwrap_or_else(|e| panic!("cannot parse {path}: {e}"));
  raw
    .into_iter()
    .map(|(k, v)| {
      let bit_len: usize = k.parse().expect("key must be numeric");
      assert_eq!(bit_len % 8, 0, "only byte-aligned vectors supported");
      let bytes = Vec::<u8>::from_hex(&v).expect("invalid hex in test vector");
      assert_eq!(bytes.len(), 64, "digest must be 64 bytes");
      let mut arr = [0u8; 64];
      arr.copy_from_slice(&bytes);
      (bit_len / 8, arr)
    })
    .collect()
}

/// Runs all NIST KAT vectors for a given hash function.
pub fn run_nist_kat(name: &str, vectors: &NistVectors, hash_fn: fn(&[u8]) -> dash_num::Hash512) {
  let mut byte_lens: Vec<usize> = vectors.keys().copied().collect();
  byte_lens.sort();
  for byte_len in byte_lens {
    let input = nist_input(byte_len);
    let expected = vectors[&byte_len];
    let got = hash_fn(input);
    assert_eq!(got.to_bytes(), expected, "{name}: mismatch at byte_len={byte_len}",);
  }
}
