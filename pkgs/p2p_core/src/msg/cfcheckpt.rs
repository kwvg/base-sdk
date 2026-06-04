//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! BIP157 compact filter checkpoint messages: getcfcheckpt, cfcheckpt.

use crate::encode::{encode_compact_size, BufferDecoder, VecEncoder, WireDecodeError, MAX_P2P_PAYLOAD};
use crate::prelude::*;
use crate::primitives::filter_type::FilterType;

use bitcoin_consensus_encoding as encoding;
use dash_primitives::wire;
use dash_primitives::BlockHash;

/// Maximum checkpoints per message.
const MAX_CFCHECKPT: usize = 1_000;

/// Requests evenly-spaced compact filter checkpoints.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct GetCFCheckpt {
  /// Filter type.
  pub filter_type: FilterType,
  /// Stop block hash.
  pub stop_hash: BlockHash,
}

impl GetCFCheckpt {
  fn decode_from_slice(data: &[u8]) -> Result<Self, WireDecodeError> {
    let sl = &mut &data[..];
    let filter_type = FilterType(wire::read_u8(sl)?);
    let stop_hash = BlockHash::from_bytes(wire::read_array(sl)?);
    Ok(Self { filter_type, stop_hash })
  }

  fn encode_to_vec(&self) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.push(self.filter_type.0);
    buf.extend_from_slice(&self.stop_hash.to_bytes());
    buf
  }
}

impl encoding::Encodable for GetCFCheckpt {
  type Encoder<'e> = VecEncoder;
  fn encoder(&self) -> Self::Encoder<'_> {
    VecEncoder::new(self.encode_to_vec())
  }
}

impl encoding::Decodable for GetCFCheckpt {
  type Decoder = BufferDecoder<GetCFCheckpt, WireDecodeError>;
  fn decoder() -> Self::Decoder {
    BufferDecoder::new(GetCFCheckpt::decode_from_slice, MAX_P2P_PAYLOAD)
  }
}

/// Response carrying filter header checkpoints at 1000-block intervals.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct CFCheckpt {
  /// Filter type.
  pub filter_type: FilterType,
  /// Stop block hash.
  pub stop_hash: BlockHash,
  /// Filter headers at every 1000th block.
  pub filter_headers: Vec<BlockHash>,
}

impl CFCheckpt {
  fn decode_from_slice(data: &[u8]) -> Result<Self, WireDecodeError> {
    let sl = &mut &data[..];
    let filter_type = FilterType(wire::read_u8(sl)?);
    let stop_hash = BlockHash::from_bytes(wire::read_array(sl)?);
    let count = wire::read_compact_size(sl, MAX_CFCHECKPT)?;
    let mut filter_headers = Vec::with_capacity(count);
    for _ in 0..count {
      filter_headers.push(BlockHash::from_bytes(wire::read_array(sl)?));
    }
    Ok(Self {
      filter_type,
      stop_hash,
      filter_headers,
    })
  }

  fn encode_to_vec(&self) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.push(self.filter_type.0);
    buf.extend_from_slice(&self.stop_hash.to_bytes());
    encode_compact_size(self.filter_headers.len(), &mut buf);
    for h in &self.filter_headers {
      buf.extend_from_slice(&h.to_bytes());
    }
    buf
  }
}

impl encoding::Encodable for CFCheckpt {
  type Encoder<'e> = VecEncoder;
  fn encoder(&self) -> Self::Encoder<'_> {
    VecEncoder::new(self.encode_to_vec())
  }
}

impl encoding::Decodable for CFCheckpt {
  type Decoder = BufferDecoder<CFCheckpt, WireDecodeError>;
  fn decoder() -> Self::Decoder {
    BufferDecoder::new(CFCheckpt::decode_from_slice, MAX_P2P_PAYLOAD)
  }
}
