//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Block header messages: getheaders, headers, sendheaders.

use crate::encode::MAX_P2P_PAYLOAD;
use crate::prelude::*;
use crate::primitives::protocol_version::ProtocolVersion;

use bitcoin_consensus_encoding as encoding;
use dash_primitives::codec::{BufferDecoder, VecEncoder};
use dash_primitives::{BlockHash, BlockHeader, MerkleRoot};
use dash_types::codec::{self, Codec, DecodeError};

/// Maximum block locator hashes.
const MAX_LOCATOR: usize = 101;
/// Maximum headers per message.
const MAX_HEADERS: usize = 2_000;

/// Requests block headers starting from a locator.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct GetHeaders {
  /// Protocol version.
  pub version: ProtocolVersion,
  /// Block locator hashes (newest first).
  pub locator_hashes: Vec<BlockHash>,
  /// Stop hash (zero to get as many as possible).
  pub hash_stop: BlockHash,
}

impl Codec for GetHeaders {
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

impl encoding::Encodable for GetHeaders {
  type Encoder<'e> = VecEncoder;
  fn encoder(&self) -> Self::Encoder<'_> {
    let mut buf = Vec::new();
    Codec::encode(self, &mut buf);
    VecEncoder::new(buf)
  }
}

impl encoding::Decodable for GetHeaders {
  type Decoder = BufferDecoder<GetHeaders, DecodeError>;
  fn decoder() -> Self::Decoder {
    BufferDecoder::new(<Self as Codec>::decode, MAX_P2P_PAYLOAD)
  }
}

/// Response carrying block headers.
///
/// Each header is followed by a CompactSize transaction count
/// (always zero, since full blocks are not included).
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct Headers {
  /// Block headers.
  pub headers: Vec<BlockHeader>,
}

impl Codec for Headers {
  fn decode(data: &mut &[u8]) -> Result<Self, DecodeError> {
    let count = codec::read_compact_size(data, MAX_HEADERS)?;
    let mut headers = Vec::with_capacity(count);
    for _ in 0..count {
      let version = codec::read_i32_le(data)?;
      let prev_hash = BlockHash::from_bytes(codec::take(data)?);
      let merkle_root = MerkleRoot::from_bytes(codec::take(data)?);
      let time = codec::read_u32_le(data)?;
      let bits = codec::read_u32_le(data)?;
      let nonce = codec::read_u32_le(data)?;
      // Consume the trailing tx_count (always 0).
      let _tx_count = codec::read_compact_size(data, 0)?;
      headers.push(BlockHeader {
        version,
        prev_hash,
        merkle_root,
        time,
        bits,
        nonce,
      });
    }
    Ok(Self { headers })
  }

  fn encode(&self, buf: &mut Vec<u8>) {
    codec::write_compact_size(self.headers.len(), buf);
    for h in &self.headers {
      buf.extend_from_slice(&h.version.to_le_bytes());
      buf.extend_from_slice(&h.prev_hash.to_bytes());
      buf.extend_from_slice(&h.merkle_root.to_bytes());
      buf.extend_from_slice(&h.time.to_le_bytes());
      buf.extend_from_slice(&h.bits.to_le_bytes());
      buf.extend_from_slice(&h.nonce.to_le_bytes());
      buf.push(0); // tx_count = 0
    }
  }
}

impl encoding::Encodable for Headers {
  type Encoder<'e> = VecEncoder;
  fn encoder(&self) -> Self::Encoder<'_> {
    let mut buf = Vec::new();
    Codec::encode(self, &mut buf);
    VecEncoder::new(buf)
  }
}

impl encoding::Decodable for Headers {
  type Decoder = BufferDecoder<Headers, DecodeError>;
  fn decoder() -> Self::Decoder {
    BufferDecoder::new(<Self as Codec>::decode, MAX_P2P_PAYLOAD)
  }
}
