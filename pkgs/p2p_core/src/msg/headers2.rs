//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Compressed header messages: getheaders2, headers2, sendheaders2.

use crate::encode::{encode_compact_size, BufferDecoder, VecEncoder, WireDecodeError, MAX_P2P_PAYLOAD};
use crate::prelude::*;
use crate::primitives::compressed_header::CompressionState;
use crate::primitives::protocol_version::ProtocolVersion;

use bitcoin_consensus_encoding as encoding;
use dash_primitives::wire;
use dash_primitives::BlockHash;

/// Maximum block locator hashes.
const MAX_LOCATOR: usize = 101;
/// Maximum headers per message.
const MAX_HEADERS: usize = 2_000;

/// Requests compressed block headers starting from a locator.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct GetHeaders2 {
  /// Protocol version.
  pub version: ProtocolVersion,
  /// Block locator hashes (newest first).
  pub locator_hashes: Vec<BlockHash>,
  /// Stop hash (zero to get as many as possible).
  pub hash_stop: BlockHash,
}

impl GetHeaders2 {
  fn decode_from_slice(data: &[u8]) -> Result<Self, WireDecodeError> {
    let sl = &mut &data[..];
    let version = ProtocolVersion(wire::read_u32_le(sl)?);
    let count = wire::read_compact_size(sl, MAX_LOCATOR)?;
    let mut locator_hashes = Vec::with_capacity(count);
    for _ in 0..count {
      locator_hashes.push(BlockHash::from_bytes(wire::read_array(sl)?));
    }
    let hash_stop = BlockHash::from_bytes(wire::read_array(sl)?);
    Ok(Self {
      version,
      locator_hashes,
      hash_stop,
    })
  }

  fn encode_to_vec(&self) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(&self.version.0.to_le_bytes());
    encode_compact_size(self.locator_hashes.len(), &mut buf);
    for h in &self.locator_hashes {
      buf.extend_from_slice(&h.to_bytes());
    }
    buf.extend_from_slice(&self.hash_stop.to_bytes());
    buf
  }
}

impl encoding::Encodable for GetHeaders2 {
  type Encoder<'e> = VecEncoder;
  fn encoder(&self) -> Self::Encoder<'_> {
    VecEncoder::new(self.encode_to_vec())
  }
}

impl encoding::Decodable for GetHeaders2 {
  type Decoder = BufferDecoder<GetHeaders2, WireDecodeError>;
  fn decoder() -> Self::Decoder {
    BufferDecoder::new(GetHeaders2::decode_from_slice, MAX_P2P_PAYLOAD)
  }
}

/// Response carrying DIP-0025 delta-compressed block headers.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct Headers2 {
  /// Fully resolved block headers (decompressed).
  pub headers: Vec<dash_primitives::BlockHeader>,
}

impl Headers2 {
  fn decode_from_slice(data: &[u8]) -> Result<Self, WireDecodeError> {
    let sl = &mut &data[..];
    let count = wire::read_compact_size(sl, MAX_HEADERS)?;
    let mut state = CompressionState::new();
    let mut headers = Vec::with_capacity(count);
    for _ in 0..count {
      headers.push(state.decode_header(sl)?);
    }
    Ok(Self { headers })
  }

  fn encode_to_vec(&self) -> Vec<u8> {
    let mut buf = Vec::new();
    encode_compact_size(self.headers.len(), &mut buf);
    let mut state = CompressionState::new();
    for h in &self.headers {
      state.encode_header(h, &mut buf);
    }
    buf
  }
}

impl encoding::Encodable for Headers2 {
  type Encoder<'e> = VecEncoder;
  fn encoder(&self) -> Self::Encoder<'_> {
    VecEncoder::new(self.encode_to_vec())
  }
}

impl encoding::Decodable for Headers2 {
  type Decoder = BufferDecoder<Headers2, WireDecodeError>;
  fn decoder() -> Self::Decoder {
    BufferDecoder::new(Headers2::decode_from_slice, MAX_P2P_PAYLOAD)
  }
}
