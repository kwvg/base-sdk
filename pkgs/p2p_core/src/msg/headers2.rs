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
