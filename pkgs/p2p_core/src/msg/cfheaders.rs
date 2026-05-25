//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! BIP157 compact filter header messages: getcfheaders, cfheaders.

use crate::encode::MAX_P2P_PAYLOAD;
use crate::prelude::*;
use crate::primitives::filter_type::FilterType;

use bitcoin_consensus_encoding as encoding;
use bitcoin_units::BlockHeight;
use dash_primitives::BlockHash;
use dash_types::codec::{self, Codec, DecodeError};
use dash_types::{BufferDecoder, VecEncoder};

/// Maximum filter hashes per message.
const MAX_CFHEADERS: usize = 2_000;

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

impl encoding::Encodable for GetCFHeaders {
  type Encoder<'e> = VecEncoder;
  fn encoder(&self) -> Self::Encoder<'_> {
    let mut buf = Vec::new();
    Codec::encode(self, &mut buf);
    VecEncoder::new(buf)
  }
}

impl encoding::Decodable for GetCFHeaders {
  type Decoder = BufferDecoder<GetCFHeaders, DecodeError>;
  fn decoder() -> Self::Decoder {
    BufferDecoder::new(<Self as Codec>::decode, MAX_P2P_PAYLOAD)
  }
}

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
    let filter_type = FilterType(codec::read_u8(data)?);
    let stop_hash = BlockHash::from_bytes(codec::take(data)?);
    let previous_filter_header = BlockHash::from_bytes(codec::take(data)?);
    let count = codec::read_compact_size(data, MAX_CFHEADERS)?;
    let mut filter_hashes = Vec::with_capacity(count);
    for _ in 0..count {
      filter_hashes.push(BlockHash::from_bytes(codec::take(data)?));
    }
    Ok(Self {
      filter_type,
      stop_hash,
      previous_filter_header,
      filter_hashes,
    })
  }

  fn encode(&self, buf: &mut Vec<u8>) {
    buf.push(self.filter_type.0);
    buf.extend_from_slice(&self.stop_hash.to_bytes());
    buf.extend_from_slice(&self.previous_filter_header.to_bytes());
    codec::write_compact_size(self.filter_hashes.len(), buf);
    for h in &self.filter_hashes {
      buf.extend_from_slice(&h.to_bytes());
    }
  }
}

impl encoding::Encodable for CFHeaders {
  type Encoder<'e> = VecEncoder;
  fn encoder(&self) -> Self::Encoder<'_> {
    let mut buf = Vec::new();
    Codec::encode(self, &mut buf);
    VecEncoder::new(buf)
  }
}

impl encoding::Decodable for CFHeaders {
  type Decoder = BufferDecoder<CFHeaders, DecodeError>;
  fn decoder() -> Self::Decoder {
    BufferDecoder::new(<Self as Codec>::decode, MAX_P2P_PAYLOAD)
  }
}
