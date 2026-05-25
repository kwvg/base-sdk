//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Governance sync request message.

use crate::prelude::*;

use dash_num::Hash256;
use dash_types::codec::{self, Codec, DecodeError};

/// Maximum bloom filter size in bytes.
const MAX_BLOOM_FILTER: usize = 36_000;

/// Requests governance objects and votes from a peer.
///
/// When `hash` is zero, the peer responds with all governance
/// objects. When non-zero, it responds with votes for that
/// specific object.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct GovSync {
  /// Object hash (zero for full sync).
  pub hash: Hash256,
  /// Serialised bloom filter (empty for no filtering).
  pub bloom_filter: Vec<u8>,
}

impl Codec for GovSync {
  fn decode(data: &mut &[u8]) -> Result<Self, DecodeError> {
    let hash = Hash256::decode(data)?;
    let bloom_filter = codec::read_blob(data, MAX_BLOOM_FILTER)?;
    Ok(Self { hash, bloom_filter })
  }

  fn encode(&self, buf: &mut Vec<u8>) {
    buf.extend_from_slice(&self.hash.to_bytes());
    codec::write_blob(&self.bloom_filter, buf);
  }
}

crate::codec::impl_p2p!(GovSync);
