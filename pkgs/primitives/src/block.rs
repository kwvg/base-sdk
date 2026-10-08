//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Dash block (header + transactions).

use crate::merkle::merkle_root_mutated;
use crate::prelude::*;
use crate::transaction::{Transaction, TxInvalid};
use crate::{codec_base, codec_type, hash_impl};

use dash_num::{make_hash, Arith256, CompactTarget, Hash256};
use dash_pow::hash as pow_hash;
use dash_types::codec::BaseCodec;
use dash_types::type_id::{TypeId, Unencodable};
use dash_types::{ArrayBuf, Checkable, Hashable, Numeric};

use core::fmt;

/// Maximum serialized transaction size (single tx, always 1 MB).
pub const MAX_LEGACY_BLOCK_SIZE: usize = 1_000_000;

/// Post-DIP0001 maximum block size (2 MB).
pub const MAX_DIP0001_BLOCK_SIZE: usize = 2_000_000;

make_hash! {
  /// Hash of a block header.
  BlockHash, 32
}

hash_impl!(BlockHash);

make_hash! {
  /// Merkle tree root hash.
  MerkleRoot, 32
}

hash_impl!(MerkleRoot);

/// A block header.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub struct BlockHeader {
  /// Block version.
  pub version: i32,
  /// Hash of the previous block header.
  pub prev_hash: BlockHash,
  /// Merkle root of the transaction tree.
  pub merkle_root: MerkleRoot,
  /// Block timestamp (unix epoch seconds).
  pub time: u32,
  /// Compact difficulty target (nBits).
  pub bits: u32,
  /// Nonce used for proof-of-work.
  pub nonce: u32,
}

codec_base!(BlockHeader {
  version,
  prev_hash,
  merkle_root,
  time,
  bits,
  nonce,
});

impl Hashable for BlockHeader {
  type Hash = BlockHash;

  fn hash(&self) -> BlockHash {
    let mut buf = ArrayBuf::<80>::new();
    self.encode(&mut buf);
    BlockHash::from(pow_hash(&buf.into_array()))
  }
}

impl fmt::Display for BlockHeader {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(
      f,
      "BlockHeader {{ version: {}, prev_hash: {}, time: {} }}",
      self.version, self.prev_hash, self.time,
    )
  }
}

/// Block validation failure.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Unencodable)]
pub enum BlockInvalid {
  /// Decoded target is negative, zero, overflows, or the hash exceeds it.
  BadProofOfWork,
  /// Computed merkle root does not match the header.
  BadMerkleRoot,
  /// `bad-blk-length`
  BadBlockLength { size: usize },
  /// `bad-cb-missing`
  MissingCoinbase,
  /// `bad-cb-multiple`
  MultipleCoinbases { index: usize },
  /// `bad-blk-sigops`
  TooManySigops { count: usize, limit: usize },
  /// A contained transaction failed validation.
  Transaction { index: usize, error: TxInvalid },
}

impl fmt::Display for BlockInvalid {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    match self {
      Self::BadProofOfWork => write!(f, "bad-proof-of-work"),
      Self::BadMerkleRoot => write!(f, "bad-merkle-root"),
      Self::BadBlockLength { size } => write!(f, "bad-blk-length: {size} bytes"),
      Self::MissingCoinbase => write!(f, "bad-cb-missing"),
      Self::MultipleCoinbases { index } => write!(f, "bad-cb-multiple: tx {index}"),
      Self::TooManySigops { count, limit } => write!(f, "bad-blk-sigops: {count} > {limit}"),
      Self::Transaction { index, error } => write!(f, "tx {index}: {error}"),
    }
  }
}

/// A Dash block: header followed by a vector of transactions.
#[derive(Clone, Debug, Eq, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct Block {
  /// Block header (80 bytes).
  pub header: BlockHeader,
  /// Transactions in the block.
  pub transactions: Vec<Transaction>,
}

codec_type!(Block { header, transactions });

impl Checkable for Block {
  type Error = BlockInvalid;

  fn check(&self) -> Option<Self::Error> {
    let pow_hash = Arith256::from(Hash256::from(self.header.hash()));
    let decoded = CompactTarget::new(self.header.bits).expand();
    if decoded.negative || decoded.value == Arith256::ZERO || decoded.overflow || pow_hash > decoded.value {
      return Some(BlockInvalid::BadProofOfWork);
    }

    let (root, _mutated) = self.merkle();
    if root != self.header.merkle_root {
      return Some(BlockInvalid::BadMerkleRoot);
    }

    if self.transactions.is_empty() {
      return Some(BlockInvalid::BadBlockLength { size: 0 });
    }

    if !self.transactions[0].is_coinbase() {
      return Some(BlockInvalid::MissingCoinbase);
    }
    for i in 1..self.transactions.len() {
      if self.transactions[i].is_coinbase() {
        return Some(BlockInvalid::MultipleCoinbases { index: i });
      }
    }

    for (i, tx) in self.transactions.iter().enumerate() {
      if let Some(e) = tx.check() {
        return Some(BlockInvalid::Transaction { index: i, error: e });
      }
    }

    let max_sigops = MAX_DIP0001_BLOCK_SIZE / 50;
    let mut total_sigops: usize = 0;
    for tx in &self.transactions {
      for input in &tx.inputs {
        total_sigops += dash_script::legacy_sigop_count(input.script_sig.as_bytes());
      }
      for output in &tx.outputs {
        total_sigops += dash_script::legacy_sigop_count(output.script_pubkey.as_bytes());
      }
    }
    if total_sigops > max_sigops {
      return Some(BlockInvalid::TooManySigops {
        count: total_sigops,
        limit: max_sigops,
      });
    }

    None
  }
}

impl Block {
  /// Computes the merkle root from the block's transactions.
  ///
  /// Returns `(root, mutated)` where `mutated` is `true` when the
  /// tree contains a duplicated-pair anomaly (CVE-2012-2459).
  pub fn merkle(&self) -> (MerkleRoot, bool) {
    let leaves: Vec<Hash256> = self
      .transactions
      .iter()
      .map(|tx| Hash256::from_lendian(*tx.hash().as_bytes()))
      .collect();
    let (root, mutated) = merkle_root_mutated(&leaves);
    (MerkleRoot::from_lendian(*root.as_bytes()), mutated)
  }
}

impl fmt::Display for Block {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "Block {{ txs: {} }}", self.transactions.len())
  }
}

#[cfg(all(test, feature = "serde"))]
#[expect(clippy::panic, clippy::unwrap_used, reason = "test code")]
mod tests {
  use super::*;

  use dash_dev::{assert_serde_rt, check_wire, Corpus};
  use rstest::rstest;

  #[rstest]
  fn corpus_block() {
    let corpus = Corpus::open(env!("CARGO_MANIFEST_DIR"), "blocks");
    let items = corpus.entries::<Block>("blocks", |raw, details, label| {
      check_wire(raw, details, label);
      if let Some(e) = details.check() {
        panic!("{label}: check: {e}");
      }
      let expected = crate::BlockHash::from_hex(label).unwrap();
      assert_eq!(details.header.hash(), expected, "{label}: pow hash");
      let (root, mutated) = details.merkle();
      assert_eq!(root, details.header.merkle_root, "{label}: merkle root");
      assert!(!mutated, "{label}: merkle mutated");
    });
    assert_serde_rt("blocks", &items);
  }
}
