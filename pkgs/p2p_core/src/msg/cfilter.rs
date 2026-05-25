//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! BIP157 compact filter messages: getcfilters, cfilter.

use crate::prelude::*;
use crate::primitives::filter_type::FilterType;

use bitcoin_units::BlockHeight;
use dash_primitives::BlockHash;
use dash_types::codec::{self, Codec, DecodeError};

/// Maximum filter data bytes.
const MAX_FILTER_DATA: usize = 256 * 1024;

/// Requests compact filters for a range of blocks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct GetCFilters {
  /// Filter type (0 = basic).
  pub filter_type: FilterType,
  /// Start height (inclusive).
  pub start_height: BlockHeight,
  /// Stop block hash (inclusive).
  pub stop_hash: BlockHash,
}

impl Codec for GetCFilters {
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

crate::codec::impl_p2p!(GetCFilters);

/// A single compact block filter.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct CFilter {
  /// Filter type.
  pub filter_type: FilterType,
  /// Block hash this filter covers.
  pub block_hash: BlockHash,
  /// Raw GCS filter data.
  pub filter_data: Vec<u8>,
}

impl Codec for CFilter {
  fn decode(data: &mut &[u8]) -> Result<Self, DecodeError> {
    Ok(Self {
      filter_type: FilterType(u8::decode(data)?),
      block_hash: BlockHash::decode(data)?,
      filter_data: codec::read_blob(data, MAX_FILTER_DATA)?,
    })
  }

  fn encode(&self, buf: &mut Vec<u8>) {
    self.filter_type.0.encode(buf);
    self.block_hash.encode(buf);
    codec::write_blob(&self.filter_data, buf);
  }
}

crate::codec::impl_p2p!(CFilter);
