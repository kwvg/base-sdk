//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Block header messages: getheaders, headers, sendheaders.

use crate::encode::MAX_P2P_PAYLOAD;
use crate::error::P2pDecodeError;
use crate::prelude::*;
use crate::primitives::protocol_version::ProtocolVersion;

use bitcoin_consensus_encoding as encoding;
use dash_primitives::codec::{BufferDecoder, VecEncoder};
use dash_primitives::{BlockHash, BlockHeader, MerkleRoot};
use dash_types::codec;

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

impl GetHeaders {
  fn decode_from_slice(data: &[u8]) -> Result<Self, P2pDecodeError> {
    let sl = &mut &data[..];
    let version = ProtocolVersion(codec::read_u32_le(sl)?);
    let count = codec::read_compact_size(sl, MAX_LOCATOR)?;
    let mut locator_hashes = Vec::with_capacity(count);
    for _ in 0..count {
      locator_hashes.push(BlockHash::from_bytes(codec::take(sl)?));
    }
    let hash_stop = BlockHash::from_bytes(codec::take(sl)?);
    Ok(Self {
      version,
      locator_hashes,
      hash_stop,
    })
  }

  fn encode_to_vec(&self) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(&self.version.0.to_le_bytes());
    codec::write_compact_size(self.locator_hashes.len(), &mut buf);
    for h in &self.locator_hashes {
      buf.extend_from_slice(&h.to_bytes());
    }
    buf.extend_from_slice(&self.hash_stop.to_bytes());
    buf
  }
}

impl encoding::Encodable for GetHeaders {
  type Encoder<'e> = VecEncoder;
  fn encoder(&self) -> Self::Encoder<'_> {
    VecEncoder::new(self.encode_to_vec())
  }
}

impl encoding::Decodable for GetHeaders {
  type Decoder = BufferDecoder<GetHeaders, P2pDecodeError>;
  fn decoder() -> Self::Decoder {
    BufferDecoder::new(GetHeaders::decode_from_slice, MAX_P2P_PAYLOAD)
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

impl Headers {
  fn decode_from_slice(data: &[u8]) -> Result<Self, P2pDecodeError> {
    let sl = &mut &data[..];
    let count = codec::read_compact_size(sl, MAX_HEADERS)?;
    let mut headers = Vec::with_capacity(count);
    for _ in 0..count {
      let version = codec::read_i32_le(sl)?;
      let prev_hash = BlockHash::from_bytes(codec::take(sl)?);
      let merkle_root = MerkleRoot::from_bytes(codec::take(sl)?);
      let time = codec::read_u32_le(sl)?;
      let bits = codec::read_u32_le(sl)?;
      let nonce = codec::read_u32_le(sl)?;
      // Consume the trailing tx_count (always 0).
      let _tx_count = codec::read_compact_size(sl, 0)?;
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

  fn encode_to_vec(&self) -> Vec<u8> {
    let mut buf = Vec::new();
    codec::write_compact_size(self.headers.len(), &mut buf);
    for h in &self.headers {
      buf.extend_from_slice(&h.version.to_le_bytes());
      buf.extend_from_slice(&h.prev_hash.to_bytes());
      buf.extend_from_slice(&h.merkle_root.to_bytes());
      buf.extend_from_slice(&h.time.to_le_bytes());
      buf.extend_from_slice(&h.bits.to_le_bytes());
      buf.extend_from_slice(&h.nonce.to_le_bytes());
      buf.push(0); // tx_count = 0
    }
    buf
  }
}

impl encoding::Encodable for Headers {
  type Encoder<'e> = VecEncoder;
  fn encoder(&self) -> Self::Encoder<'_> {
    VecEncoder::new(self.encode_to_vec())
  }
}

impl encoding::Decodable for Headers {
  type Decoder = BufferDecoder<Headers, P2pDecodeError>;
  fn decoder() -> Self::Decoder {
    BufferDecoder::new(Headers::decode_from_slice, MAX_P2P_PAYLOAD)
  }
}
