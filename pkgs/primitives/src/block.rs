//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Dash block (header + transactions).

use crate::block_header::BlockHeader;
use crate::prelude::*;
use crate::transaction::{Transaction, TxInvalid};
use crate::validation::{DeploymentContext, MAX_DIP0001_BLOCK_SIZE, MAX_LEGACY_BLOCK_SIZE};

use dash_types::codec::{Codec, DecodeError};

use core::fmt;

/// A Dash block: header followed by a vector of transactions.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct Block {
  /// Block header (80 bytes).
  pub header: BlockHeader,
  /// Transactions in the block.
  pub transactions: Vec<Transaction>,
}

impl Codec for Block {
  fn decode(data: &mut &[u8]) -> Result<Self, DecodeError> {
    Ok(Self {
      header: BlockHeader::decode(data)?,
      transactions: Vec::decode(data)?,
    })
  }

  fn encode(&self, buf: &mut Vec<u8>) {
    self.header.encode(buf);
    self.transactions.encode(buf);
  }
}

dash_types::impl_type!(Block);

impl fmt::Display for Block {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "Block {{ txs: {} }}", self.transactions.len())
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
