//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! BIP157 compact filter header messages: getcfheaders, cfheaders.

use crate::prelude::*;
use crate::primitives::filter_type::FilterType;

use bitcoin_units::BlockHeight;
use dash_primitives::BlockHash;
use dash_types::codec::{Codec, DecodeError};

/// Requests compact filter headers for a range of blocks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct GetCFHeaders {
  /// Filter type.
  pub filter_type: FilterType,
  /// Start height (inclusive).
  pub start_height: BlockHeight,
  /// Stop block hash (inclusive).
  pub stop_hash: BlockHash,
}

impl Codec for GetCFHeaders {
  fn decode(data: &mut &[u8]) -> Result<Self, DecodeError> {
    Ok(Self {
      filter_type: FilterType(u8::decode(data)?),
      start_height: BlockHeight::from_u32(u32::decode(data)?),
      stop_hash: BlockHash::decode(data)?,
    })
  }

  fn encode(&self, buf: &mut Vec<u8>) {
    self.filter_type.0.encode(buf);
    self.start_height.to_u32().encode(buf);
    self.stop_hash.encode(buf);
  }
}

crate::codec::impl_p2p!(GetCFHeaders);

/// Response carrying filter headers and their hashes.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct CFHeaders {
  /// Filter type.
  pub filter_type: FilterType,
  /// Hash of the stop block.
  pub stop_hash: BlockHash,
  /// Previous filter header (for chaining).
  pub previous_filter_header: BlockHash,
  /// Filter hashes in block-height order.
  pub filter_hashes: Vec<BlockHash>,
}

impl Codec for CFHeaders {
  fn decode(data: &mut &[u8]) -> Result<Self, DecodeError> {
    Ok(Self {
      filter_type: FilterType(u8::decode(data)?),
      stop_hash: BlockHash::decode(data)?,
      previous_filter_header: BlockHash::decode(data)?,
      filter_hashes: Vec::decode(data)?,
    })
  }

  fn encode(&self, buf: &mut Vec<u8>) {
    self.filter_type.0.encode(buf);
    self.stop_hash.encode(buf);
    self.previous_filter_header.encode(buf);
    self.filter_hashes.encode(buf);
  }
}

crate::codec::impl_p2p!(CFHeaders);
