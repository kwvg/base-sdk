//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Merkle root computation and partial merkle trees.

use crate::block::MAX_DIP0001_BLOCK_SIZE;
use crate::codec_type;
use crate::prelude::*;

use bitcoin_hashes::sha256d;
use dash_num::Hash256;
use dash_types::type_id::{TypeId, Unencodable};
use dash_types::{Checkable, Numeric};

use core::fmt;

/// Upper bound on the transaction count of a partial merkle tree, since a
/// serialized transaction takes at least 60 bytes.
pub const MAX_PARTIAL_MERKLE_TRANSACTIONS: u32 = (MAX_DIP0001_BLOCK_SIZE / 60) as u32;

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

/// Partial merkle tree failure.
#[derive(Clone, Debug, Eq, Hash, PartialEq, Unencodable)]
pub enum PartialMerkleTreeInvalid {
  /// The tree covers no transactions.
  NoTransactions,
  /// The transaction count exceeds [`MAX_PARTIAL_MERKLE_TRANSACTIONS`].
  TooManyTransactions { count: u32 },
  /// The tree holds more hashes than transactions.
  TooManyHashes { hashes: usize, transactions: u32 },
  /// The flag bits are fewer than the hashes.
  TooFewBits { bits: usize, hashes: usize },
  /// The traversal needs more flag bits than the tree holds.
  BitsExhausted,
  /// The traversal needs more hashes than the tree holds.
  HashesExhausted,
  /// Two sibling branches have the same hash.
  DuplicateBranch,
  /// Whole flag bytes remain after the traversal.
  UnusedBits,
  /// Hashes remain after the traversal.
  UnusedHashes,
}

impl fmt::Display for PartialMerkleTreeInvalid {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    match self {
      Self::NoTransactions => write!(f, "partial merkle tree covers no transactions"),
      Self::TooManyTransactions { count } => {
        write!(
          f,
          "partial merkle tree covers {count} transactions, limit {MAX_PARTIAL_MERKLE_TRANSACTIONS}"
        )
      }
      Self::TooManyHashes { hashes, transactions } => {
        write!(
          f,
          "partial merkle tree holds {hashes} hashes for {transactions} transactions"
        )
      }
      Self::TooFewBits { bits, hashes } => write!(f, "partial merkle tree holds {bits} bits for {hashes} hashes"),
      Self::BitsExhausted => write!(f, "partial merkle tree ran out of flag bits"),
      Self::HashesExhausted => write!(f, "partial merkle tree ran out of hashes"),
      Self::DuplicateBranch => write!(f, "partial merkle tree has identical sibling branches"),
      Self::UnusedBits => write!(f, "partial merkle tree has unused flag bytes"),
      Self::UnusedHashes => write!(f, "partial merkle tree has unused hashes"),
    }
  }
}

/// A subset of a block's transaction hashes with the branches that prove them
/// against the block's merkle root.
#[derive(Clone, Debug, Default, Eq, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub struct PartialMerkleTree {
  transactions: u32,
  hashes: Vec<Hash256>,
  #[cfg_attr(feature = "serde", serde(with = "dash_types::serialize::hex"))]
  flags: Vec<u8>,
}

codec_type!(PartialMerkleTree {
  transactions,
  hashes,
  flags
});

/// The merkle root a partial merkle tree proves and its matched hashes.
#[derive(Clone, Debug, Eq, Hash, PartialEq, Unencodable)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct MerkleMatches {
  /// Merkle root of the whole block.
  pub root: Hash256,
  /// Matched transaction hashes with their positions in the block.
  pub matched: Vec<(u32, Hash256)>,
}

impl Checkable for PartialMerkleTree {
  type Error = PartialMerkleTreeInvalid;

  fn check(&self) -> Option<Self::Error> {
    if self.transactions == 0 {
      return Some(PartialMerkleTreeInvalid::NoTransactions);
    }
    if self.transactions > MAX_PARTIAL_MERKLE_TRANSACTIONS {
      return Some(PartialMerkleTreeInvalid::TooManyTransactions {
        count: self.transactions,
      });
    }
    if self.hashes.len() > self.transactions as usize {
      return Some(PartialMerkleTreeInvalid::TooManyHashes {
        hashes: self.hashes.len(),
        transactions: self.transactions,
      });
    }
    let bits = self.flags.len() * 8;
    if bits < self.hashes.len() {
      return Some(PartialMerkleTreeInvalid::TooFewBits {
        bits,
        hashes: self.hashes.len(),
      });
    }
    None
  }
}

impl PartialMerkleTree {
  /// Builds a tree from its transaction count, depth-first hashes and flag
  /// bits packed least significant bit first.
  pub fn new(transactions: u32, hashes: Vec<Hash256>, flags: Vec<u8>) -> Self {
    Self {
      transactions,
      hashes,
      flags,
    }
  }

  /// Total transaction count of the block.
  pub fn transactions(&self) -> u32 {
    self.transactions
  }

  /// Hashes in depth-first order.
  pub fn hashes(&self) -> &[Hash256] {
    &self.hashes
  }

  /// Packed flag bits, padding included.
  pub fn flags(&self) -> &[u8] {
    &self.flags
  }

  /// Recovers the merkle root and the matched hashes. The caller compares
  /// the root with the block header to authenticate the matches.
  ///
  /// # Errors
  ///
  /// Returns the [`Checkable`] failure of the tree, or the traversal failure
  /// when the bits and hashes do not describe exactly one tree.
  pub fn extract_matches(&self) -> Result<MerkleMatches, PartialMerkleTreeInvalid> {
    if let Some(e) = self.check() {
      return Err(e);
    }

    let mut height = 0;
    while self.width(height) > 1 {
      height += 1;
    }

    let mut used = (0, 0);
    let mut matched = Vec::new();
    let root = self.extract(height, 0, &mut used, &mut matched)?;
    let (bits_used, hashes_used): (usize, usize) = used;
    if bits_used.div_ceil(8) != self.flags.len() {
      return Err(PartialMerkleTreeInvalid::UnusedBits);
    }
    if hashes_used != self.hashes.len() {
      return Err(PartialMerkleTreeInvalid::UnusedHashes);
    }
    Ok(MerkleMatches { root, matched })
  }

  /// Walks the subtree at `height` and `pos`, advancing `used`, the counts of
  /// consumed bits and hashes.
  fn extract(
    &self,
    height: u32,
    pos: u64,
    used: &mut (usize, usize),
    matched: &mut Vec<(u32, Hash256)>,
  ) -> Result<Hash256, PartialMerkleTreeInvalid> {
    let parent_of_match = self.bit(used.0).ok_or(PartialMerkleTreeInvalid::BitsExhausted)?;
    used.0 += 1;

    if height == 0 || !parent_of_match {
      let hash = *self
        .hashes
        .get(used.1)
        .ok_or(PartialMerkleTreeInvalid::HashesExhausted)?;
      used.1 += 1;
      if height == 0 && parent_of_match {
        // A leaf position is below the transaction count, which is a `u32`.
        matched.push((pos as u32, hash));
      }
      return Ok(hash);
    }

    let left = self.extract(height - 1, pos * 2, used, matched)?;
    let right = if pos * 2 + 1 < self.width(height - 1) {
      let right = self.extract(height - 1, pos * 2 + 1, used, matched)?;
      if right == left {
        return Err(PartialMerkleTreeInvalid::DuplicateBranch);
      }
      right
    } else {
      left
    };
    Ok(hash_pair(&left, &right))
  }

  fn width(&self, height: u32) -> u64 {
    (u64::from(self.transactions) + (1u64 << height) - 1) >> height
  }

  fn bit(&self, index: usize) -> Option<bool> {
    self.flags.get(index / 8).map(|byte| byte >> (index % 8) & 1 == 1)
  }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "test code")]
mod tests {
  use super::{
    merkle_root, merkle_root_mutated, MerkleMatches, PartialMerkleTree, PartialMerkleTreeInvalid,
    MAX_PARTIAL_MERKLE_TRANSACTIONS,
  };
  use crate::prelude::*;
  use crate::TxHash;

  use bitcoin_hashes::sha256d;
  use dash_num::Hash256;
  use dash_types::codec::BaseCodec;
  use dash_types::{Checkable, Numeric};
  use hex_conservative::hex;
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

  fn tree(transactions: u32, hashes: &[Hash256], flags: &[u8]) -> PartialMerkleTree {
    PartialMerkleTree::new(transactions, hashes.to_vec(), flags.to_vec())
  }

  #[rstest]
  #[case::no_transactions(tree(0, &[], &[]), PartialMerkleTreeInvalid::NoTransactions)]
  #[case::too_many_transactions(
    tree(MAX_PARTIAL_MERKLE_TRANSACTIONS + 1, &[leaf(1)], &[0x00]),
    PartialMerkleTreeInvalid::TooManyTransactions { count: MAX_PARTIAL_MERKLE_TRANSACTIONS + 1 },
  )]
  #[case::too_many_hashes(
    tree(1, &[leaf(1), leaf(2)], &[0x00]),
    PartialMerkleTreeInvalid::TooManyHashes { hashes: 2, transactions: 1 },
  )]
  #[case::too_few_bits(
    tree(9, &[leaf(1); 9], &[0x00]),
    PartialMerkleTreeInvalid::TooFewBits { bits: 8, hashes: 9 },
  )]
  fn check_rejects_malformed_trees(#[case] tree: PartialMerkleTree, #[case] fault: PartialMerkleTreeInvalid) {
    assert_eq!(tree.check(), Some(fault.clone()));
    assert_eq!(tree.extract_matches(), Err(fault));
  }

  #[rstest]
  fn check_admits_the_transaction_limit() {
    let tree = tree(MAX_PARTIAL_MERKLE_TRANSACTIONS, &[leaf(1)], &[0x00]);
    assert_eq!(MAX_PARTIAL_MERKLE_TRANSACTIONS, 33_333);
    assert_eq!(tree.check(), None);
  }

  #[rstest]
  #[case::bits_exhausted(tree(1, &[], &[]), PartialMerkleTreeInvalid::BitsExhausted)]
  #[case::hashes_exhausted(tree(1, &[], &[0x00]), PartialMerkleTreeInvalid::HashesExhausted)]
  #[case::duplicate_branch(tree(2, &[leaf(1), leaf(1)], &[0x01]), PartialMerkleTreeInvalid::DuplicateBranch)]
  #[case::unused_bits(tree(1, &[leaf(1)], &[0x00, 0x00]), PartialMerkleTreeInvalid::UnusedBits)]
  #[case::unused_hashes(tree(2, &[leaf(1), leaf(2)], &[0x00]), PartialMerkleTreeInvalid::UnusedHashes)]
  fn extract_rejects_inconsistent_traversals(#[case] tree: PartialMerkleTree, #[case] fault: PartialMerkleTreeInvalid) {
    assert_eq!(tree.check(), None);
    assert_eq!(tree.extract_matches(), Err(fault));
  }

  /// Three leaves with the middle one matched; the flag bits read 1, 1, 0, 1, 0
  /// in depth-first order and the unmatched right branch carries `H(c, c)`.
  #[rstest]
  fn extract_recovers_the_root_and_the_match() {
    let (a, b, c) = (leaf(1), leaf(2), leaf(3));
    let tree = tree(3, &[a, b, parent(c, c)], &[0b0000_1011]);
    assert_eq!(
      tree.extract_matches(),
      Ok(MerkleMatches {
        root: merkle_root(&[a, b, c]),
        matched: vec![(1, b)],
      })
    );
  }

  /// Unread bits in the last flag byte are padding, which the tree keeps.
  #[rstest]
  fn flag_padding_survives_a_round_trip() {
    let tree = tree(1, &[leaf(1)], &[0xFE]);
    assert_eq!(tree.extract_matches().map(|m| m.root), Ok(leaf(1)));

    let mut buf = Vec::new();
    tree.encode(&mut buf);
    assert_eq!(PartialMerkleTree::decode(&mut buf.as_slice()), Ok(tree));
  }

  /// `cbTxMerkleTree` of the `mnlistdiff` corpus entry in `p2p_core` for block
  /// 000000000000001571c885183cffca87096388f24eb8452f6f22b202b20226c8.
  const MNLISTDIFF_TREE: [u8; 168] = hex!(concat!(
    "0a000000",
    "05",
    "6e2b2b9bda7063781a5da9d55a57ef9b5e027716a8b27a52bb9edeb107e03d35",
    "ec2dfd9f7ef700f9a684539567a62b6a0abb02c37781182808f6c199bfe70f74",
    "c3874d6059dad9ae33733d5409b120c27b3e81426f6255cd36f9b0ef9c9820ee",
    "8511c009a25ff17a8a0f3af600ec08304a7b9a33cd0c3bc29d13ca4a34391fda",
    "adc518611257943637535e2962c1b90addb07b33ac8984efd950029bf76bf02a",
    "02",
    "1f00",
  ));

  /// Coinbase txid of block
  /// 000000000000001571c885183cffca87096388f24eb8452f6f22b202b20226c8.
  const MNLISTDIFF_COINBASE: &str = "353de007b1de9ebb527ab2a81677025e9bef575ad5a95d1a786370da9b2b2b6e";

  #[rstest]
  fn mnlistdiff_tree_proves_its_coinbase() {
    let tree = PartialMerkleTree::decode(&mut MNLISTDIFF_TREE.as_slice()).unwrap();
    let mut buf = Vec::new();
    tree.encode(&mut buf);
    assert_eq!(buf, MNLISTDIFF_TREE);
    assert_eq!(
      (tree.transactions(), tree.hashes().len(), tree.flags()),
      (10, 5, &[0x1F, 0x00][..])
    );

    let matches = tree.extract_matches().unwrap();
    let coinbase = Hash256::from_lendian(*TxHash::from_hex(MNLISTDIFF_COINBASE).unwrap().as_bytes());
    assert_eq!(matches.matched, vec![(0, coinbase)]);
  }
}
