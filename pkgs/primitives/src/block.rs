//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Dash block (header + transactions).

use crate::block_header::{BlockHeader, BlockHeaderDecoder, BlockHeaderDecoderError, BlockHeaderEncoder};
use crate::prelude::*;
use crate::transaction::{Transaction, TransactionDecoderError, TxInvalid};
use crate::validation::{DeploymentContext, MAX_DIP0001_BLOCK_SIZE, MAX_LEGACY_BLOCK_SIZE};

use bitcoin_consensus_encoding as encoding;

use core::fmt;

/// A Dash block: header followed by a vector of transactions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Block {
  /// Block header (80 bytes).
  pub header: BlockHeader,
  /// Transactions in the block.
  pub transactions: Vec<Transaction>,
}

impl fmt::Display for Block {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "Block {{ txs: {} }}", self.transactions.len())
  }
}

// Ecosystem encoding traits.

encoding::encoder_newtype! {
  /// Encoder for [`Block`].
  pub struct BlockEncoder<'e>(
    encoding::Encoder2<
      BlockHeaderEncoder<'e>,
      encoding::Encoder2<
        encoding::CompactSizeEncoder,
        encoding::SliceEncoder<'e, Transaction>,
      >,
    >
  );
}

impl encoding::Encodable for Block {
  type Encoder<'e> = BlockEncoder<'e>;

  fn encoder(&self) -> Self::Encoder<'_> {
    BlockEncoder::new(encoding::Encoder2::new(
      self.header.encoder(),
      encoding::Encoder2::new(
        encoding::CompactSizeEncoder::new(self.transactions.len()),
        encoding::SliceEncoder::without_length_prefix(&self.transactions),
      ),
    ))
  }
}

/// Decoder for [`Block`].
#[derive(Debug)]
pub struct BlockDecoder(encoding::Decoder2<BlockHeaderDecoder, encoding::VecDecoder<Transaction>>);

impl BlockDecoder {
  /// Constructs a new decoder.
  pub const fn new() -> Self {
    Self(encoding::Decoder2::new(
      BlockHeaderDecoder::new(),
      encoding::VecDecoder::new(),
    ))
  }
}

impl Default for BlockDecoder {
  fn default() -> Self {
    Self::new()
  }
}

/// Decode error for [`Block`].
#[derive(Debug)]
pub enum BlockDecoderError {
  /// Failed to decode the header.
  Header(BlockHeaderDecoderError),
  /// Failed to decode a transaction.
  Transaction(encoding::VecDecoderError<TransactionDecoderError>),
}

impl fmt::Display for BlockDecoderError {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    match self {
      Self::Header(e) => write!(f, "block header: {e}"),
      Self::Transaction(e) => write!(f, "block tx: {e}"),
    }
  }
}

impl encoding::Decoder for BlockDecoder {
  type Output = Block;
  type Error = BlockDecoderError;

  #[inline]
  fn push_bytes(&mut self, bytes: &mut &[u8]) -> Result<bool, Self::Error> {
    self.0.push_bytes(bytes).map_err(|e| match e {
      encoding::Decoder2Error::First(e) => BlockDecoderError::Header(e),
      encoding::Decoder2Error::Second(e) => BlockDecoderError::Transaction(e),
    })
  }

  #[inline]
  fn end(self) -> Result<Self::Output, Self::Error> {
    let (header, transactions) = self.0.end().map_err(|e| match e {
      encoding::Decoder2Error::First(e) => BlockDecoderError::Header(e),
      encoding::Decoder2Error::Second(e) => BlockDecoderError::Transaction(e),
    })?;
    Ok(Block { header, transactions })
  }

  #[inline]
  fn read_limit(&self) -> usize {
    self.0.read_limit()
  }
}

impl encoding::Decodable for Block {
  type Decoder = BlockDecoder;
  fn decoder() -> Self::Decoder {
    BlockDecoder::new()
  }
}

/// Block validation failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BlockInvalid {
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
      Self::BadBlockLength { size } => write!(f, "bad-blk-length: {size} bytes"),
      Self::MissingCoinbase => write!(f, "bad-cb-missing"),
      Self::MultipleCoinbases { index } => write!(f, "bad-cb-multiple: tx {index}"),
      Self::TooManySigops { count, limit } => write!(f, "bad-blk-sigops: {count} > {limit}"),
      Self::Transaction { index, error } => write!(f, "tx {index}: {error}"),
    }
  }
}

impl Block {
  /// Validates block structure without chain context.
  ///
  /// Does not check proof-of-work or the merkle root; those require data not
  /// available from the block alone.
  ///
  /// # Errors
  ///
  /// Returns the first validation error encountered.
  pub fn validate(&self, ctx: &DeploymentContext) -> Result<(), BlockInvalid> {
    let max_block_size = match ctx.dip0001_active {
      Some(true) => MAX_DIP0001_BLOCK_SIZE,
      Some(false) => MAX_LEGACY_BLOCK_SIZE,
      None => MAX_DIP0001_BLOCK_SIZE,
    };

    if self.transactions.is_empty() {
      return Err(BlockInvalid::BadBlockLength { size: 0 });
    }

    if !self.transactions[0].is_coinbase() {
      return Err(BlockInvalid::MissingCoinbase);
    }
    for i in 1..self.transactions.len() {
      if self.transactions[i].is_coinbase() {
        return Err(BlockInvalid::MultipleCoinbases { index: i });
      }
    }

    for (i, tx) in self.transactions.iter().enumerate() {
      tx.validate(ctx)
        .map_err(|e| BlockInvalid::Transaction { index: i, error: e })?;
    }

    let max_sigops = max_block_size / 50;
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
      return Err(BlockInvalid::TooManySigops {
        count: total_sigops,
        limit: max_sigops,
      });
    }

    Ok(())
  }
}

/// Returns `(start, end)` byte offsets for each transaction in a raw serialized
/// block.
///
/// Walks the block without full deserialization; only the transaction
/// boundaries are tracked. Useful for indexing and selective extraction.
///
/// # Errors
///
/// Returns an error if the block header, transaction count, or any individual
/// transaction cannot be decoded.
pub fn tx_byte_ranges(raw_block: &[u8]) -> Result<Vec<(usize, usize)>, crate::error::DecodeError> {
  use crate::wire;

  let sl = &mut &raw_block[..];

  // Skip 80-byte header.
  let _ = wire::read_bytes(sl, 80)?;

  let tx_count = wire::read_compact_size(sl, 100_000)?;
  let mut ranges = Vec::with_capacity(tx_count);

  for _ in 0..tx_count {
    let start = raw_block.len() - sl.len();
    let _tx = encoding::decode_from_slice_unbounded::<Transaction>(sl).map_err(|_| crate::error::DecodeError::Eof {
      needed: 1,
      remaining: 0,
    })?;
    let end = raw_block.len() - sl.len();
    ranges.push((start, end));
  }

  Ok(ranges)
}
