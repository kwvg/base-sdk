//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! BIP157 compact filter header messages: getcfheaders, cfheaders.

use crate::encode::{encode_compact_size, BufferDecoder, VecEncoder, WireDecodeError, MAX_P2P_PAYLOAD};
use crate::prelude::*;
use crate::primitives::filter_type::FilterType;

use bitcoin_consensus_encoding as encoding;
use bitcoin_units::BlockHeight;
use dash_primitives::wire;
use dash_primitives::BlockHash;

/// Maximum filter hashes per message.
const MAX_CFHEADERS: usize = 2_000;

/// Requests compact filter headers for a range of blocks.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct GetCFHeaders {
  /// Filter type.
  pub filter_type: FilterType,
  /// Start height (inclusive).
  pub start_height: BlockHeight,
  /// Stop block hash (inclusive).
  pub stop_hash: BlockHash,
}

impl GetCFHeaders {
  fn decode_from_slice(data: &[u8]) -> Result<Self, WireDecodeError> {
    let sl = &mut &data[..];
    let filter_type = FilterType(wire::read_u8(sl)?);
    let start_height = BlockHeight::from_u32(wire::read_u32_le(sl)?);
    let stop_hash = BlockHash::from_bytes(wire::read_array(sl)?);
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

impl encoding::Encodable for GetCFHeaders {
  type Encoder<'e> = VecEncoder;
  fn encoder(&self) -> Self::Encoder<'_> {
    VecEncoder::new(self.encode_to_vec())
  }
}

impl encoding::Decodable for GetCFHeaders {
  type Decoder = BufferDecoder<GetCFHeaders, WireDecodeError>;
  fn decoder() -> Self::Decoder {
    BufferDecoder::new(GetCFHeaders::decode_from_slice, MAX_P2P_PAYLOAD)
  }
}

/// Response carrying filter headers and their hashes.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
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

impl CFHeaders {
  fn decode_from_slice(data: &[u8]) -> Result<Self, WireDecodeError> {
    let sl = &mut &data[..];
    let filter_type = FilterType(wire::read_u8(sl)?);
    let stop_hash = BlockHash::from_bytes(wire::read_array(sl)?);
    let previous_filter_header = BlockHash::from_bytes(wire::read_array(sl)?);
    let count = wire::read_compact_size(sl, MAX_CFHEADERS)?;
    let mut filter_hashes = Vec::with_capacity(count);
    for _ in 0..count {
      filter_hashes.push(BlockHash::from_bytes(wire::read_array(sl)?));
    }
    Ok(Self {
      filter_type,
      stop_hash,
      previous_filter_header,
      filter_hashes,
    })
  }

  fn encode_to_vec(&self) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.push(self.filter_type.0);
    buf.extend_from_slice(&self.stop_hash.to_bytes());
    buf.extend_from_slice(&self.previous_filter_header.to_bytes());
    encode_compact_size(self.filter_hashes.len(), &mut buf);
    for h in &self.filter_hashes {
      buf.extend_from_slice(&h.to_bytes());
    }
    buf
  }
}

impl encoding::Encodable for CFHeaders {
  type Encoder<'e> = VecEncoder;
  fn encoder(&self) -> Self::Encoder<'_> {
    VecEncoder::new(self.encode_to_vec())
  }
}

impl encoding::Decodable for CFHeaders {
  type Decoder = BufferDecoder<CFHeaders, WireDecodeError>;
  fn decoder() -> Self::Decoder {
    BufferDecoder::new(CFHeaders::decode_from_slice, MAX_P2P_PAYLOAD)
  }
}
