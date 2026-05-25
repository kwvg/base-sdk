//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! BIP157 compact filter messages: getcfilters, cfilter.

use crate::encode::MAX_P2P_PAYLOAD;
use crate::error::P2pDecodeError;
use crate::prelude::*;
use crate::primitives::filter_type::FilterType;

use bitcoin_consensus_encoding as encoding;
use bitcoin_units::BlockHeight;
use dash_primitives::codec::{BufferDecoder, VecEncoder};
use dash_primitives::BlockHash;
use dash_types::codec;

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

impl GetCFilters {
  fn decode_from_slice(data: &[u8]) -> Result<Self, P2pDecodeError> {
    let sl = &mut &data[..];
    let filter_type = FilterType(codec::read_u8(sl)?);
    let start_height = BlockHeight::from_u32(codec::read_u32_le(sl)?);
    let stop_hash = BlockHash::from_bytes(codec::take(sl)?);
    Ok(Self {
      filter_type,
      start_height,
      stop_hash,
    })
  }

  fn encode_to_vec(&self) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.push(self.filter_type.0);
    buf.extend_from_slice(&self.start_height.to_u32().to_le_bytes());
    buf.extend_from_slice(&self.stop_hash.to_bytes());
    buf
  }
}

impl encoding::Encodable for GetCFilters {
  type Encoder<'e> = VecEncoder;
  fn encoder(&self) -> Self::Encoder<'_> {
    VecEncoder::new(self.encode_to_vec())
  }
}

impl encoding::Decodable for GetCFilters {
  type Decoder = BufferDecoder<GetCFilters, P2pDecodeError>;
  fn decoder() -> Self::Decoder {
    BufferDecoder::new(GetCFilters::decode_from_slice, MAX_P2P_PAYLOAD)
  }
}

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

impl CFilter {
  fn decode_from_slice(data: &[u8]) -> Result<Self, P2pDecodeError> {
    let sl = &mut &data[..];
    let filter_type = FilterType(codec::read_u8(sl)?);
    let block_hash = BlockHash::from_bytes(codec::take(sl)?);
    let len = codec::read_compact_size(sl, MAX_FILTER_DATA)?;
    let filter_data = codec::read_bytes(sl, len)?.to_vec();
    Ok(Self {
      filter_type,
      block_hash,
      filter_data,
    })
  }

  fn encode_to_vec(&self) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.push(self.filter_type.0);
    buf.extend_from_slice(&self.block_hash.to_bytes());
    codec::write_compact_size(self.filter_data.len(), &mut buf);
    buf.extend_from_slice(&self.filter_data);
    buf
  }
}

impl encoding::Encodable for CFilter {
  type Encoder<'e> = VecEncoder;
  fn encoder(&self) -> Self::Encoder<'_> {
    VecEncoder::new(self.encode_to_vec())
  }
}

impl encoding::Decodable for CFilter {
  type Decoder = BufferDecoder<CFilter, P2pDecodeError>;
  fn decoder() -> Self::Decoder {
    BufferDecoder::new(CFilter::decode_from_slice, MAX_P2P_PAYLOAD)
  }
}
