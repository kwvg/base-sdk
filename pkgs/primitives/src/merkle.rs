//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Merkle root computation.

use bitcoin_hashes::sha256d;
use dash_num::Hash256;
use dash_types::Numeric;

/// Computes the merkle root of `leaves`, or the null hash for no leaves.
pub fn merkle_root(leaves: &[Hash256]) -> Hash256 {
  merkle_root_mutated(leaves).0
}

/// Computes the merkle root of `leaves` along with a mutation flag.
///
/// The flag is `true` when a row pairs two equal hashes. A list with such a
/// pair shares its root with a shorter list (CVE-2012-2459), so the flag lets
/// a caller reject the duplicate.
pub fn merkle_root_mutated(leaves: &[Hash256]) -> (Hash256, bool) {
  if leaves.is_empty() {
    return (Hash256::default(), false);
  }

  let mut hashes = leaves.to_vec();
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
      hashes[i] = hash_pair(&hashes[left], &hashes[right]);
    }
    hashes.truncate(half);
  }

  (hashes[0], mutated)
}

fn hash_pair(left: &Hash256, right: &Hash256) -> Hash256 {
  let mut combined = [0u8; 64];
  combined[..32].copy_from_slice(left.as_bytes());
  combined[32..].copy_from_slice(right.as_bytes());
  Hash256::from_lendian(sha256d::Hash::hash(&combined).to_byte_array())
}

#[cfg(test)]
mod tests {
  use super::{merkle_root, merkle_root_mutated};
  use crate::prelude::*;

  use bitcoin_hashes::sha256d;
  use dash_num::Hash256;
  use dash_types::Numeric;
  use rstest::rstest;

  fn leaf(byte: u8) -> Hash256 {
    Hash256::from_lendian([byte; 32])
  }

  fn parent(left: Hash256, right: Hash256) -> Hash256 {
    let mut combined = [0u8; 64];
    combined[..32].copy_from_slice(left.as_bytes());
    combined[32..].copy_from_slice(right.as_bytes());
    Hash256::from_lendian(sha256d::Hash::hash(&combined).to_byte_array())
  }

  #[rstest]
  fn empty_list_has_the_null_root() {
    assert_eq!(merkle_root_mutated(&[]), (Hash256::default(), false));
  }

  #[rstest]
  fn single_leaf_is_its_own_root() {
    assert_eq!(merkle_root_mutated(&[leaf(1)]), (leaf(1), false));
  }

  #[rstest]
  fn odd_row_pairs_its_last_hash_with_itself() {
    let (a, b, c) = (leaf(1), leaf(2), leaf(3));
    let expected = parent(parent(a, b), parent(c, c));
    assert_eq!(merkle_root_mutated(&[a, b, c]), (expected, false));
  }

  #[rstest]
  fn duplicated_pair_sets_mutated() {
    let (a, b, c) = (leaf(1), leaf(2), leaf(3));
    let (root, mutated) = merkle_root_mutated(&[a, b, c, c]);
    assert_eq!(root, merkle_root(&[a, b, c]));
    assert!(mutated);
  }

  #[rstest]
  #[case::first_row(vec![leaf(1), leaf(1)])]
  #[case::second_row(vec![leaf(1), leaf(2), leaf(1), leaf(2)])]
  fn equal_siblings_set_mutated_in_any_row(#[case] leaves: Vec<Hash256>) {
    assert!(merkle_root_mutated(&leaves).1);
  }
}
