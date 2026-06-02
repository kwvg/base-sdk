//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Inventory vector used by inv, getdata, and notfound messages.

use bitcoin_consensus_encoding as encoding;
use dash_num::Hash256;

use core::fmt;

/// Inventory object type.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum InvType {
  /// Error / not used.
  Error,
  /// Transaction.
  Tx,
  /// Block.
  Block,
  /// Filtered block (BIP37).
  FilteredBlock,
  /// Compact block (BIP152).
  CompactBlock,
  /// Governance object.
  GovernanceObject,
  /// Governance object vote.
  GovernanceObjectVote,
  /// Unknown or unhandled type.
  Unknown(u32),
}

impl InvType {
  /// Converts from the on-wire `u32`.
  pub const fn from_u32(v: u32) -> Self {
    match v {
      0 => Self::Error,
      1 => Self::Tx,
      2 => Self::Block,
      3 => Self::FilteredBlock,
      4 => Self::CompactBlock,
      17 => Self::GovernanceObject,
      18 => Self::GovernanceObjectVote,
      other => Self::Unknown(other),
    }
  }

  /// Returns the on-wire `u32` value.
  pub const fn to_u32(self) -> u32 {
    match self {
      Self::Error => 0,
      Self::Tx => 1,
      Self::Block => 2,
      Self::FilteredBlock => 3,
      Self::CompactBlock => 4,
      Self::GovernanceObject => 17,
      Self::GovernanceObjectVote => 18,
      Self::Unknown(v) => v,
    }
  }
}

impl fmt::Display for InvType {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    match self {
      Self::Error => f.write_str("error"),
      Self::Tx => f.write_str("tx"),
      Self::Block => f.write_str("block"),
      Self::FilteredBlock => f.write_str("filtered_block"),
      Self::CompactBlock => f.write_str("compact_block"),
      Self::GovernanceObject => f.write_str("governance_object"),
      Self::GovernanceObjectVote => f.write_str("governance_object_vote"),
      Self::Unknown(v) => write!(f, "unknown({v})"),
    }
  }
}

/// An inventory vector: a typed 32-byte hash.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct Inventory {
  /// Object type.
  pub inv_type: InvType,
  /// Object hash.
  pub hash: Hash256,
}

impl fmt::Display for Inventory {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "{}:{}", self.inv_type, self.hash)
  }
}

type InventoryInnerEncoder = encoding::Encoder2<encoding::ArrayEncoder<4>, encoding::ArrayEncoder<32>>;

encoding::encoder_newtype_exact! {
  /// Encoder for [`Inventory`].
  pub struct InventoryEncoder<'e>(InventoryInnerEncoder);
}

impl encoding::Encodable for Inventory {
  type Encoder<'e> = InventoryEncoder<'e>;
  fn encoder(&self) -> Self::Encoder<'_> {
    InventoryEncoder::new(encoding::Encoder2::new(
      encoding::ArrayEncoder::without_length_prefix(self.inv_type.to_u32().to_le_bytes()),
      encoding::ArrayEncoder::without_length_prefix(self.hash.to_bytes()),
    ))
  }
}

type InventoryInnerDecoder = encoding::Decoder2<encoding::ArrayDecoder<4>, encoding::ArrayDecoder<32>>;

/// Decoder for [`Inventory`].
#[derive(Clone, Debug)]
pub struct InventoryDecoder(InventoryInnerDecoder);

/// Decode error for [`Inventory`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InventoryDecoderError(<InventoryInnerDecoder as encoding::Decoder>::Error);

impl fmt::Display for InventoryDecoderError {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "inventory decode: {}", self.0)
  }
}

impl encoding::Decoder for InventoryDecoder {
  type Output = Inventory;
  type Error = InventoryDecoderError;

  fn push_bytes(&mut self, bytes: &mut &[u8]) -> Result<bool, Self::Error> {
    self.0.push_bytes(bytes).map_err(InventoryDecoderError)
  }

  fn end(self) -> Result<Self::Output, Self::Error> {
    let (ty, hash_bytes) = self.0.end().map_err(InventoryDecoderError)?;
    let inv_type = InvType::from_u32(u32::from_le_bytes(ty));
    let hash = Hash256::from_bytes(hash_bytes);
    Ok(Inventory { inv_type, hash })
  }

  fn read_limit(&self) -> usize {
    self.0.read_limit()
  }
}

impl encoding::Decodable for Inventory {
  type Decoder = InventoryDecoder;
  fn decoder() -> Self::Decoder {
    InventoryDecoder(encoding::Decoder2::new(
      encoding::ArrayDecoder::<4>::new(),
      encoding::ArrayDecoder::<32>::new(),
    ))
  }
}
