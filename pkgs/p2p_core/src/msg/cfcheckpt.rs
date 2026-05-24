//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! BIP157 compact filter checkpoint messages: getcfcheckpt, cfcheckpt.

use crate::encode::MAX_P2P_PAYLOAD;
use crate::prelude::*;
use crate::primitives::filter_type::FilterType;

use bitcoin_consensus_encoding as encoding;
use dash_primitives::codec::{BufferDecoder, VecEncoder};
use dash_primitives::BlockHash;
use dash_types::codec::{self, Codec, DecodeError};

/// Maximum checkpoints per message.
const MAX_CFCHECKPT: usize = 1_000;

/// Requests evenly-spaced compact filter checkpoints.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct GetCFCheckpt {
  /// Filter type.
  pub filter_type: FilterType,
  /// Stop block hash.
  pub stop_hash: BlockHash,
}

impl Codec for GetCFCheckpt {
  fn decode(data: &mut &[u8]) -> Result<Self, DecodeError> {
    let filter_type = FilterType(codec::read_u8(data)?);
    let stop_hash = BlockHash::from_bytes(codec::take(data)?);
    Ok(Self { filter_type, stop_hash })
  }

  fn encode(&self, buf: &mut Vec<u8>) {
    buf.push(self.filter_type.0);
    buf.extend_from_slice(&self.stop_hash.to_bytes());
  }
}

impl encoding::Encodable for GetCFCheckpt {
  type Encoder<'e> = VecEncoder;
  fn encoder(&self) -> Self::Encoder<'_> {
    let mut buf = Vec::new();
    Codec::encode(self, &mut buf);
    VecEncoder::new(buf)
  }
}

impl encoding::Decodable for GetCFCheckpt {
  type Decoder = BufferDecoder<GetCFCheckpt, DecodeError>;
  fn decoder() -> Self::Decoder {
    BufferDecoder::new(<Self as Codec>::decode, MAX_P2P_PAYLOAD)
  }
}

/// Response carrying filter header checkpoints at 1000-block intervals.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct CFCheckpt {
  /// Filter type.
  pub filter_type: FilterType,
  /// Stop block hash.
  pub stop_hash: BlockHash,
  /// Filter headers at every 1000th block.
  pub filter_headers: Vec<BlockHash>,
}

impl Codec for CFCheckpt {
  fn decode(data: &mut &[u8]) -> Result<Self, DecodeError> {
    let filter_type = FilterType(codec::read_u8(data)?);
    let stop_hash = BlockHash::from_bytes(codec::take(data)?);
    let count = codec::read_compact_size(data, MAX_CFCHECKPT)?;
    let mut filter_headers = Vec::with_capacity(count);
    for _ in 0..count {
      filter_headers.push(BlockHash::from_bytes(codec::take(data)?));
    }
    Ok(Self {
      filter_type,
      stop_hash,
      filter_headers,
    })
  }

  fn encode(&self, buf: &mut Vec<u8>) {
    buf.push(self.filter_type.0);
    buf.extend_from_slice(&self.stop_hash.to_bytes());
    codec::write_compact_size(self.filter_headers.len(), buf);
    for h in &self.filter_headers {
      buf.extend_from_slice(&h.to_bytes());
    }
  }
}

impl encoding::Encodable for CFCheckpt {
  type Encoder<'e> = VecEncoder;
  fn encoder(&self) -> Self::Encoder<'_> {
    let mut buf = Vec::new();
    Codec::encode(self, &mut buf);
    VecEncoder::new(buf)
  }
}

impl encoding::Decodable for CFCheckpt {
  type Decoder = BufferDecoder<CFCheckpt, DecodeError>;
  fn decoder() -> Self::Decoder {
    BufferDecoder::new(<Self as Codec>::decode, MAX_P2P_PAYLOAD)
  }
}
