//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Masternode list diff messages: getmnlistd, mnlistdiff.

use crate::prelude::*;
use crate::primitives::mn_list::MnListDiffPayload;

use dash_primitives::BlockHash;
use dash_types::codec::{Codec, DecodeError};

/// Requests a masternode list diff between two blocks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct GetMnListDiff {
  /// Base block hash (beginning of range).
  pub base_block_hash: BlockHash,
  /// Target block hash (end of range).
  pub block_hash: BlockHash,
}

impl Codec for GetMnListDiff {
  fn decode(data: &mut &[u8]) -> Result<Self, DecodeError> {
    let base_block_hash = BlockHash::decode(data)?;
    let block_hash = BlockHash::decode(data)?;
    Ok(Self {
      base_block_hash,
      block_hash,
    })
  }

  fn encode(&self, buf: &mut Vec<u8>) {
    buf.extend_from_slice(self.base_block_hash.as_bytes());
    buf.extend_from_slice(self.block_hash.as_bytes());
  }
}

crate::codec::impl_p2p!(GetMnListDiff);

/// Response carrying the masternode list diff.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct MnListDiff {
  /// The full diff payload.
  pub payload: MnListDiffPayload,
}

impl Codec for MnListDiff {
  fn decode(data: &mut &[u8]) -> Result<Self, DecodeError> {
    MnListDiffPayload::decode(data).map(|payload| Self { payload })
  }

  fn encode(&self, buf: &mut Vec<u8>) {
    self.payload.encode(buf);
  }
}

crate::codec::impl_p2p!(MnListDiff);
