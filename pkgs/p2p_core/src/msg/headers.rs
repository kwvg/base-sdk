//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Block header messages: getheaders, headers, sendheaders.

use crate::prelude::*;
use crate::primitives::protocol_version::ProtocolVersion;

use dash_primitives::{BlockHash, BlockHeader, MerkleRoot};
use dash_types::codec::{self, Codec, DecodeError};

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
    Ok(Self {
      version: ProtocolVersion(u32::decode(data)?),
      locator_hashes: Vec::decode(data)?,
      hash_stop: BlockHash::decode(data)?,
    })
  }

  fn encode(&self, buf: &mut Vec<u8>) {
    self.version.0.encode(buf);
    self.locator_hashes.encode(buf);
    self.hash_stop.encode(buf);
  }
}

crate::codec::impl_p2p!(GetHeaders);

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
      headers.push(BlockHeader {
        version: i32::decode(data)?,
        prev_hash: BlockHash::decode(data)?,
        merkle_root: MerkleRoot::decode(data)?,
        time: u32::decode(data)?,
        bits: u32::decode(data)?,
        nonce: u32::decode(data)?,
      });
      // Consume the trailing tx_count (always 0).
      codec::read_compact_size(data, 0)?;
    }
    Ok(Self { headers })
  }

  fn encode(&self, buf: &mut Vec<u8>) {
    codec::write_compact_size(self.headers.len(), buf);
    for h in &self.headers {
      h.version.encode(buf);
      h.prev_hash.encode(buf);
      h.merkle_root.encode(buf);
      h.time.encode(buf);
      h.bits.encode(buf);
      h.nonce.encode(buf);
      0u8.encode(buf); // tx_count = 0
    }
  }
}

crate::codec::impl_p2p!(Headers);
