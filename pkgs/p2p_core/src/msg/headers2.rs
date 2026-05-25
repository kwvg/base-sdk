//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Compressed header messages: getheaders2, headers2, sendheaders2.

use crate::prelude::*;
use crate::primitives::compressed_header::CompressionState;
use crate::primitives::protocol_version::ProtocolVersion;

use dash_primitives::BlockHash;
use dash_types::codec::{self, Codec, DecodeError};

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
    let locator_hashes = codec::read_vec(data, MAX_LOCATOR)?;
    let hash_stop = BlockHash::decode(data)?;
    Ok(Self {
      version,
      locator_hashes,
      hash_stop,
    })
  }

  fn encode(&self, buf: &mut Vec<u8>) {
    buf.extend_from_slice(&self.version.0.to_le_bytes());
    codec::write_vec(&self.locator_hashes, buf);
    buf.extend_from_slice(&self.hash_stop.to_bytes());
  }
}

crate::codec::impl_p2p!(GetHeaders2);

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

crate::codec::impl_p2p!(Headers2);
