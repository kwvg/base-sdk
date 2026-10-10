//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Dash block (header + transactions).

use crate::merkle::{merkle_root, merkle_root_mutated};
use crate::payload::{SpecialPayload, TxType};
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
  /// `bad-txns-duplicate`
  DuplicateTransaction,
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
  /// `bad-cbtx-assetunlockmerkleroot`
  AssetUnlockMerkleRoot,
}

impl fmt::Display for BlockInvalid {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    match self {
      Self::BadProofOfWork => write!(f, "high-hash"),
      Self::BadMerkleRoot => write!(f, "bad-txnmrklroot"),
      Self::DuplicateTransaction => write!(f, "bad-txns-duplicate"),
      Self::BadBlockLength { size } => write!(f, "bad-blk-length: {size} bytes"),
      Self::MissingCoinbase => write!(f, "bad-cb-missing"),
      Self::MultipleCoinbases { index } => write!(f, "bad-cb-multiple: tx {index}"),
      Self::TooManySigops { count, limit } => write!(f, "bad-blk-sigops: {count} > {limit}"),
      Self::Transaction { index, error } => write!(f, "tx {index}: {error}"),
      Self::AssetUnlockMerkleRoot => write!(f, "bad-cbtx-assetunlockmerkleroot"),
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

    let (root, mutated) = self.merkle();
    if root != self.header.merkle_root {
      return Some(BlockInvalid::BadMerkleRoot);
    }
    if mutated {
      return Some(BlockInvalid::DuplicateTransaction);
    }
    if self
      .committed_asset_unlock_root()
      .is_some_and(|root| root != self.asset_unlock_merkle_root())
    {
      return Some(BlockInvalid::AssetUnlockMerkleRoot);
    }

    let mut encoded = Vec::new();
    self.encode(&mut encoded);
    let size = encoded.len();
    if self.transactions.is_empty() || self.transactions.len() > MAX_DIP0001_BLOCK_SIZE || size > MAX_DIP0001_BLOCK_SIZE
    {
      return Some(BlockInvalid::BadBlockLength { size });
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

  /// Computes the merkle root of the instance hashes of the asset unlocks
  /// with a stable txid, in block order. Without such unlocks the root is
  /// null.
  pub fn asset_unlock_merkle_root(&self) -> MerkleRoot {
    let leaves: Vec<Hash256> = self
      .transactions
      .iter()
      .filter(|tx| tx.has_stable_txid())
      .map(|tx| Hash256::from_lendian(*tx.instance_hash().as_bytes()))
      .collect();
    MerkleRoot::from_lendian(*merkle_root(&leaves).as_bytes())
  }

  /// Returns the asset unlock root of a first transaction that carries a
  /// coinbase commitment of version 4 or later. A payload that does not
  /// decode commits to nothing.
  fn committed_asset_unlock_root(&self) -> Option<MerkleRoot> {
    let first = self
      .transactions
      .first()
      .filter(|tx| tx.tx_type == TxType::CoinbaseCommitment)?;
    match first.decode_payload()? {
      Ok(SpecialPayload::CoinbaseCommitment(cbtx)) => cbtx.merkle_root_asset_unlocks(),
      _ => None,
    }
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

  #[rstest]
  #[case::proof_of_work(BlockInvalid::BadProofOfWork, "high-hash")]
  #[case::merkle_root(BlockInvalid::BadMerkleRoot, "bad-txnmrklroot")]
  #[case::duplicate(BlockInvalid::DuplicateTransaction, "bad-txns-duplicate")]
  #[case::asset_unlock_root(BlockInvalid::AssetUnlockMerkleRoot, "bad-cbtx-assetunlockmerkleroot")]
  fn reasons_use_the_reference_strings(#[case] error: BlockInvalid, #[case] reason: &str) {
    assert_eq!(error.to_string(), reason);
  }

  fn genesis() -> Block {
    let corpus = Corpus::open(env!("CARGO_MANIFEST_DIR"), "blocks");
    corpus
      .entries::<Block>("blocks", |_, _, _| {})
      .remove("00000ffd590b1485b3caadc19b22e6379c733355108f107a430458cdf3407ab6")
      .unwrap()
  }

  /// Gives an edited block its merkle root, the easiest target and a nonce
  /// that meets it, so the checks after the proof of work decide.
  fn seal(block: &mut Block) {
    block.header.merkle_root = block.merkle().0;
    block.header.bits = 0x207f_ffff;
    while block.check() == Some(BlockInvalid::BadProofOfWork) {
      block.header.nonce += 1;
    }
  }

  fn wire_len<T: BaseCodec>(item: &T) -> usize {
    let mut buf = Vec::new();
    item.encode(&mut buf);
    buf.len()
  }

  /// Builds a spend of `size` bytes, for sizes that need a five-byte script
  /// length prefix.
  fn spend(index: u32, size: usize) -> Transaction {
    let mut tx = Transaction {
      version: 1,
      tx_type: crate::TxType::Spend,
      inputs: vec![crate::TxIn {
        prevout: crate::OutPoint {
          hash: crate::TxHash::from_lendian([0x11; 32]),
          index,
        },
        script_sig: bitcoin_primitives::script::ScriptSigBuf::new(),
        sequence: u32::MAX,
      }],
      outputs: vec![crate::TxOut {
        value: bitcoin_units::Amount::ZERO,
        script_pubkey: bitcoin_primitives::script::ScriptPubKeyBuf::from_bytes(vec![0x00; 0x1_0000]),
      }],
      lock_time: 0,
      extra_payload: Vec::new(),
    };
    let overhead = wire_len(&tx) - 0x1_0000;
    tx.outputs[0].script_pubkey = bitcoin_primitives::script::ScriptPubKeyBuf::from_bytes(vec![0x00; size - overhead]);
    tx
  }

  #[rstest]
  #[case::at_the_limit(0, None)]
  #[case::past_the_limit(1, Some(BlockInvalid::BadBlockLength { size: MAX_DIP0001_BLOCK_SIZE + 1 }))]
  fn serialized_size_is_capped_at_the_dip0001_block_size(
    #[case] excess: usize,
    #[case] expected: Option<BlockInvalid>,
  ) {
    let mut block = genesis();
    // One spend this large exceeds the transaction cap, so two fill the block.
    let fill = MAX_DIP0001_BLOCK_SIZE - wire_len(&block) + excess;
    block.transactions.push(spend(0, fill / 2));
    block.transactions.push(spend(1, fill - fill / 2));
    assert_eq!(wire_len(&block), MAX_DIP0001_BLOCK_SIZE + excess);

    seal(&mut block);
    assert_eq!(block.check(), expected);
  }

  #[rstest]
  fn null_first_input_with_more_inputs_is_a_missing_coinbase() {
    let mut block = genesis();

    let mut extra = block.transactions[0].inputs[0].clone();
    extra.prevout = crate::OutPoint {
      hash: crate::TxHash::from_lendian([0x11; 32]),
      index: 0,
    };
    block.transactions[0].inputs.push(extra);
    seal(&mut block);
    assert_eq!(block.check(), Some(BlockInvalid::MissingCoinbase));
  }

  /// Appending a copy of the last transaction to an odd list leaves the
  /// merkle root unchanged, so only the mutation flag exposes the duplicate.
  #[rstest]
  #[case::three_txs("0000000000000001bc04663e2eb95852a8b30963e5a40c089ad6d675f620bc21")]
  #[case::five_txs("000000000000001bf41cff06b76780050682ca29e61a91c391893d4745579777")]
  fn duplicated_last_transaction_is_rejected(#[case] label: &str) {
    let corpus = Corpus::open(env!("CARGO_MANIFEST_DIR"), "blocks");
    let mut block = corpus.entries::<Block>("blocks", |_, _, _| {}).remove(label).unwrap();
    assert_eq!(block.transactions.len() % 2, 1, "{label}: odd transaction count");
    assert_eq!(block.check(), None, "{label}: unmodified block");

    let last = block.transactions.last().unwrap().clone();
    block.transactions.push(last);
    assert_eq!(block.merkle(), (block.header.merkle_root, true));
    assert_eq!(block.check(), Some(BlockInvalid::DuplicateTransaction));
  }

  /// Returns the stable-txid corpus unlock of payload version 2, or of
  /// version 1 for any other `version`.
  fn asset_unlock(version: u8) -> Transaction {
    let label = match version {
      2 => "2b3ff94b9041aff5b77c42631894290a6f9993c645c935e2ebe27a62b17bc20b",
      _ => "65fc488b35abd172726238a16cc71ef11eecb034ce05991e9a3e5ba4fd85094f",
    };
    let corpus = Corpus::open(env!("CARGO_MANIFEST_DIR"), "stabletxid");
    let mut raws = BTreeMap::new();
    corpus.entries::<crate::TxHash>("stabletxid", |raw, _, label| {
      raws.insert(String::from(label), raw.to_vec());
    });
    Transaction::decode(&mut raws[label].as_slice()).unwrap()
  }

  /// A mainnet block of one coinbase, its commitment raised to `version`
  /// with `unlocks` as the asset unlock root, sealed after `txs` join it.
  /// Version 3 fields the commitment lacks start empty.
  fn block_committing(version: u16, unlocks: Option<MerkleRoot>, txs: Vec<Transaction>) -> Block {
    let corpus = Corpus::open(env!("CARGO_MANIFEST_DIR"), "blocks");
    let mut block = corpus
      .entries::<Block>("blocks", |_, _, _| {})
      .remove("0000000000000006547ad092244695ef3c1b815aebb31b7ab196d2aaa10891cb")
      .unwrap();
    let Some(Ok(SpecialPayload::CoinbaseCommitment(cbtx))) = block.transactions[0].decode_payload() else {
      panic!("the corpus block carries a coinbase commitment");
    };
    let raised = crate::CoinbaseCommitment::new(
      version,
      cbtx.height,
      cbtx.merkle_root_mn_list,
      cbtx.merkle_root_quorums(),
      cbtx.best_cl_height_diff().or(Some(0)),
      cbtx
        .best_cl_signature()
        .map_or(Some([0; 96]), |sig| Some(*sig.as_bytes())),
      cbtx.credit_pool_balance().or(Some(0)),
      unlocks,
    )
    .unwrap();
    block.transactions[0].extra_payload.clear();
    raised.encode(&mut block.transactions[0].extra_payload);
    block.transactions.extend(txs);
    seal(&mut block);
    block
  }

  fn instance_root(tx: &Transaction) -> Option<MerkleRoot> {
    Some(MerkleRoot::from_lendian(*tx.instance_hash().as_bytes()))
  }

  #[rstest]
  fn asset_unlock_root_covers_only_stable_txids() {
    let (v1, v2) = (asset_unlock(1), asset_unlock(2));
    let block = block_committing(4, Some(MerkleRoot::default()), vec![v1.clone(), v2.clone(), v1]);
    // One leaf is its own root.
    assert_eq!(Some(block.asset_unlock_merkle_root()), instance_root(&v2));
  }

  #[rstest]
  #[case::matching_root(4, instance_root(&asset_unlock(2)), None)]
  #[case::null_root(4, Some(MerkleRoot::default()), Some(BlockInvalid::AssetUnlockMerkleRoot))]
  #[case::stable_txid_root(
    4,
    Some(MerkleRoot::from_lendian(*asset_unlock(2).hash().as_bytes())),
    Some(BlockInvalid::AssetUnlockMerkleRoot)
  )]
  #[case::v3_commits_nothing(3, None, None)]
  fn coinbase_commits_to_asset_unlock_instances(
    #[case] version: u16,
    #[case] unlocks: Option<MerkleRoot>,
    #[case] expected: Option<BlockInvalid>,
  ) {
    let block = block_committing(version, unlocks, vec![asset_unlock(2)]);
    assert_eq!(block.check(), expected);
  }

  #[rstest]
  fn block_without_unlocks_commits_to_the_null_root() {
    let block = block_committing(4, Some(MerkleRoot::default()), Vec::new());
    assert_eq!(block.check(), None);
    let block = block_committing(4, Some(MerkleRoot::from_lendian([0x44; 32])), Vec::new());
    assert_eq!(block.check(), Some(BlockInvalid::AssetUnlockMerkleRoot));
  }
}
