//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Inventory vector used by inv, getdata, and notfound messages.

use crate::prelude::*;

use dash_num::Hash256;
use dash_types::codec::{self, Codec, DecodeError, NumCodec};

use core::fmt;

/// Inventory object type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
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

impl NumCodec<u32> for InvType {
  fn from_base(v: u32) -> Self {
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

  fn to_base(&self) -> u32 {
    match self {
      Self::Error => 0,
      Self::Tx => 1,
      Self::Block => 2,
      Self::FilteredBlock => 3,
      Self::CompactBlock => 4,
      Self::GovernanceObject => 17,
      Self::GovernanceObjectVote => 18,
      Self::Unknown(v) => *v,
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

dash_types::impl_num!(InvType, u32);

/// An inventory vector: a typed 32-byte hash.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct Inventory {
  /// Object type.
  pub inv_type: InvType,
  /// Object hash.
  pub hash: Hash256,
}

impl Codec for Inventory {
  fn decode(data: &mut &[u8]) -> Result<Self, DecodeError> {
    let inv_type = InvType::from_base(codec::read_u32_le(data)?);
    let hash = Hash256::decode(data)?;
    Ok(Self { inv_type, hash })
  }

  fn encode(&self, buf: &mut Vec<u8>) {
    buf.extend_from_slice(&self.inv_type.to_base().to_le_bytes());
    buf.extend_from_slice(&self.hash.to_bytes());
  }
}

crate::codec::impl_p2p!(Inventory);

impl fmt::Display for Inventory {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "{}:{}", self.inv_type, self.hash)
  }
}
