//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Dash block header (80 bytes).

use crate::prelude::*;
use crate::{BlockHash, MerkleRoot};

use dash_types::codec::{Codec, DecodeError};

use core::fmt;

/// A Dash block header (80 bytes on the wire).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
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

impl Codec for BlockHeader {
  fn decode(data: &mut &[u8]) -> Result<Self, DecodeError> {
    Ok(Self {
      version: i32::decode(data)?,
      prev_hash: BlockHash::decode(data)?,
      merkle_root: MerkleRoot::decode(data)?,
      time: u32::decode(data)?,
      bits: u32::decode(data)?,
      nonce: u32::decode(data)?,
    })
  }

  fn encode(&self, buf: &mut Vec<u8>) {
    self.version.encode(buf);
    self.prev_hash.encode(buf);
    self.merkle_root.encode(buf);
    self.time.encode(buf);
    self.bits.encode(buf);
    self.nonce.encode(buf);
  }
}

dash_types::impl_type!(BlockHeader);

impl fmt::Display for BlockHeader {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(
      f,
      "BlockHeader {{ version: {}, prev_hash: {}, time: {} }}",
      self.version, self.prev_hash, self.time,
    )
  }
}
