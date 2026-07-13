//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Shared benchmark helpers.

#![allow(dead_code)]

pub fn test_ikm(i: u8) -> [u8; 32] {
  let mut ikm = [0u8; 32];
  ikm[0] = i;
  ikm[31] = i.wrapping_add(1);
  ikm
}

pub fn test_msg(i: u8) -> [u8; 32] {
  let mut m = [0u8; 32];
  m[0] = i.wrapping_mul(7);
  m[15] = i;
  m
}

pub fn make_id(i: u32) -> dash_num::Hash256 {
  let mut bytes = [0u8; 32];
  bytes[28..32].copy_from_slice(&i.to_be_bytes());
  dash_num::Hash256::from_bytes(bytes)
}

pub fn sequential_ids(n: usize) -> Vec<dash_num::Hash256> {
  (1..=n).map(|i| make_id(i as u32)).collect()
}
