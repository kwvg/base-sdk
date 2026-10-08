//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Merkle root computation.

use crate::block::MerkleRoot;
use crate::prelude::*;
use crate::transaction::TxHash;

use bitcoin_hashes::sha256d;
use dash_num::Hash256;
use dash_types::Numeric;

/// Computes the merkle root from a list of transaction hashes.
///
/// Returns `(root, mutated)` where `mutated` is `true` when a
/// duplicated last-element pair was detected (CVE-2012-2459).
pub(crate) fn compute_merkle_root(leaves: &[TxHash]) -> (MerkleRoot, bool) {
  if leaves.is_empty() {
    return (MerkleRoot::default(), false);
  }

  let mut hashes: Vec<Hash256> = leaves.iter().map(|h| Hash256::from_lendian(*h.as_bytes())).collect();
  let mut mutated = false;

  while hashes.len() > 1 {
    let len = hashes.len();
    let half = len.div_ceil(2);
    for i in 0..half {
      let left = i * 2;
      let right = if left + 1 < len { left + 1 } else { left };
      if left != right && hashes[left] == hashes[right] {
        mutated = true;
      }
      let mut combined = [0u8; 64];
      combined[..32].copy_from_slice(hashes[left].as_bytes());
      combined[32..].copy_from_slice(hashes[right].as_bytes());
      hashes[i] = Hash256::from_lendian(sha256d::Hash::hash(&combined).to_byte_array());
    }
    hashes.truncate(half);
  }

  (MerkleRoot::from_lendian(*hashes[0].as_bytes()), mutated)
}
