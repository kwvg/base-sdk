//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Compressed header messages: getheaders2, headers2, sendheaders2.

use crate::encode::MAX_P2P_PAYLOAD;
use crate::prelude::*;
use crate::primitives::compressed_header::CompressionState;
use crate::primitives::protocol_version::ProtocolVersion;

use bitcoin_consensus_encoding as encoding;
use dash_primitives::BlockHash;
use dash_types::codec::{self, Codec, DecodeError};
use dash_types::{BufferDecoder, VecEncoder};

/// Maximum block locator hashes.
const MAX_LOCATOR: usize = 101;
/// Maximum headers per message.
const MAX_HEADERS: usize = 2_000;

/// Requests compressed block headers starting from a locator.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct GetHeaders2 {
  /// Protocol version.
  pub version: ProtocolVersion,
  /// Block locator hashes (newest first).
  pub locator_hashes: Vec<BlockHash>,
  /// Stop hash (zero to get as many as possible).
  pub hash_stop: BlockHash,
}

impl Codec for GetHeaders2 {
  fn decode(data: &mut &[u8]) -> Result<Self, DecodeError> {
    let version = ProtocolVersion(codec::read_u32_le(data)?);
    let count = codec::read_compact_size(data, MAX_LOCATOR)?;
    let mut locator_hashes = Vec::with_capacity(count);
    for _ in 0..count {
      locator_hashes.push(BlockHash::from_bytes(codec::take(data)?));
    }
    let hash_stop = BlockHash::from_bytes(codec::take(data)?);
    Ok(Self {
      version,
      locator_hashes,
      hash_stop,
    })
  }

  fn encode(&self, buf: &mut Vec<u8>) {
    buf.extend_from_slice(&self.version.0.to_le_bytes());
    codec::write_compact_size(self.locator_hashes.len(), buf);
    for h in &self.locator_hashes {
      buf.extend_from_slice(&h.to_bytes());
    }
    buf.extend_from_slice(&self.hash_stop.to_bytes());
  }
}

impl encoding::Encodable for GetHeaders2 {
  type Encoder<'e> = VecEncoder;
  fn encoder(&self) -> Self::Encoder<'_> {
    let mut buf = Vec::new();
    Codec::encode(self, &mut buf);
    VecEncoder::new(buf)
  }
}

impl encoding::Decodable for GetHeaders2 {
  type Decoder = BufferDecoder<GetHeaders2, DecodeError>;
  fn decoder() -> Self::Decoder {
    BufferDecoder::new(<Self as Codec>::decode, MAX_P2P_PAYLOAD)
  }
}

/// Response carrying DIP-0025 delta-compressed block headers.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct Headers2 {
  /// Fully resolved block headers (decompressed).
  pub headers: Vec<dash_primitives::BlockHeader>,
}

impl Codec for Headers2 {
  fn decode(data: &mut &[u8]) -> Result<Self, DecodeError> {
    let count = codec::read_compact_size(data, MAX_HEADERS)?;
    let mut state = CompressionState::new();
    let mut headers = Vec::with_capacity(count);
    for _ in 0..count {
      headers.push(state.decode_header(data)?);
    }
    Ok(Self { headers })
  }

  fn encode(&self, buf: &mut Vec<u8>) {
    codec::write_compact_size(self.headers.len(), buf);
    let mut state = CompressionState::new();
    for h in &self.headers {
      state.encode_header(h, buf);
    }
  }
}

impl encoding::Encodable for Headers2 {
  type Encoder<'e> = VecEncoder;
  fn encoder(&self) -> Self::Encoder<'_> {
    let mut buf = Vec::new();
    Codec::encode(self, &mut buf);
    VecEncoder::new(buf)
  }
}

impl encoding::Decodable for Headers2 {
  type Decoder = BufferDecoder<Headers2, DecodeError>;
  fn decoder() -> Self::Decoder {
    BufferDecoder::new(<Self as Codec>::decode, MAX_P2P_PAYLOAD)
  }
}
