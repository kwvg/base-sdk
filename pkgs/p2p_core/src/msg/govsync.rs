//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Governance sync request message.

use crate::encode::{encode_compact_size, BufferDecoder, VecEncoder, WireDecodeError, MAX_P2P_PAYLOAD};
use crate::prelude::*;

use bitcoin_consensus_encoding as encoding;
use dash_num::Hash256;
use dash_primitives::wire;

/// Maximum bloom filter size in bytes.
const MAX_BLOOM_FILTER: usize = 36_000;

/// Requests governance objects and votes from a peer.
///
/// When `hash` is zero, the peer responds with all governance
/// objects. When non-zero, it responds with votes for that
/// specific object.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct GovSync {
  /// Object hash (zero for full sync).
  pub hash: Hash256,
  /// Serialised bloom filter (empty for no filtering).
  pub bloom_filter: Vec<u8>,
}

impl GovSync {
  fn decode_from_slice(data: &[u8]) -> Result<Self, WireDecodeError> {
    let sl = &mut &data[..];
    let hash = Hash256::from_bytes(wire::read_array(sl)?);
    let len = wire::read_compact_size(sl, MAX_BLOOM_FILTER)?;
    let bloom_filter = wire::read_bytes(sl, len)?.to_vec();
    Ok(Self { hash, bloom_filter })
  }

  fn encode_to_vec(&self) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(&self.hash.to_bytes());
    encode_compact_size(self.bloom_filter.len(), &mut buf);
    buf.extend_from_slice(&self.bloom_filter);
    buf
  }
}

impl encoding::Encodable for GovSync {
  type Encoder<'e> = VecEncoder;
  fn encoder(&self) -> Self::Encoder<'_> {
    VecEncoder::new(self.encode_to_vec())
  }
}

impl encoding::Decodable for GovSync {
  type Decoder = BufferDecoder<GovSync, WireDecodeError>;
  fn decoder() -> Self::Decoder {
    BufferDecoder::new(GovSync::decode_from_slice, MAX_P2P_PAYLOAD)
  }
}
