//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! BIP157 compact filter messages: getcfilters, cfilter.

use crate::encode::MAX_P2P_PAYLOAD;
use crate::prelude::*;
use crate::primitives::filter_type::FilterType;

use bitcoin_consensus_encoding as encoding;
use bitcoin_units::BlockHeight;
use dash_primitives::BlockHash;
use dash_types::codec::{self, Codec, DecodeError};
use dash_types::{BufferDecoder, VecEncoder};

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
    let filter_type = FilterType(codec::read_u8(data)?);
    let start_height = BlockHeight::from_u32(codec::read_u32_le(data)?);
    let stop_hash = BlockHash::from_bytes(codec::take(data)?);
    Ok(Self {
      filter_type,
      start_height,
      stop_hash,
    })
  }

  fn encode(&self, buf: &mut Vec<u8>) {
    buf.push(self.filter_type.0);
    buf.extend_from_slice(&self.start_height.to_u32().to_le_bytes());
    buf.extend_from_slice(&self.stop_hash.to_bytes());
  }
}

impl encoding::Encodable for GetCFilters {
  type Encoder<'e> = VecEncoder;
  fn encoder(&self) -> Self::Encoder<'_> {
    let mut buf = Vec::new();
    Codec::encode(self, &mut buf);
    VecEncoder::new(buf)
  }
}

impl encoding::Decodable for GetCFilters {
  type Decoder = BufferDecoder<GetCFilters, DecodeError>;
  fn decoder() -> Self::Decoder {
    BufferDecoder::new(<Self as Codec>::decode, MAX_P2P_PAYLOAD)
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

impl Codec for CFilter {
  fn decode(data: &mut &[u8]) -> Result<Self, DecodeError> {
    let filter_type = FilterType(codec::read_u8(data)?);
    let block_hash = BlockHash::from_bytes(codec::take(data)?);
    let len = codec::read_compact_size(data, MAX_FILTER_DATA)?;
    let filter_data = codec::read_bytes(data, len)?.to_vec();
    Ok(Self {
      filter_type,
      block_hash,
      filter_data,
    })
  }

  fn encode(&self, buf: &mut Vec<u8>) {
    buf.push(self.filter_type.0);
    buf.extend_from_slice(&self.block_hash.to_bytes());
    codec::write_compact_size(self.filter_data.len(), buf);
    buf.extend_from_slice(&self.filter_data);
  }
}

impl encoding::Encodable for CFilter {
  type Encoder<'e> = VecEncoder;
  fn encoder(&self) -> Self::Encoder<'_> {
    let mut buf = Vec::new();
    Codec::encode(self, &mut buf);
    VecEncoder::new(buf)
  }
}

impl encoding::Decodable for CFilter {
  type Decoder = BufferDecoder<CFilter, DecodeError>;
  fn decoder() -> Self::Decoder {
    BufferDecoder::new(<Self as Codec>::decode, MAX_P2P_PAYLOAD)
  }
}
