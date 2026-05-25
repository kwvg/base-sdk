//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Governance sync request message.

use crate::prelude::*;

use dash_num::Hash256;
use dash_types::codec::{Codec, DecodeError};

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
    Ok(Self {
      hash: Hash256::decode(data)?,
      bloom_filter: Vec::decode(data)?,
    })
  }

  fn encode(&self, buf: &mut Vec<u8>) {
    self.hash.encode(buf);
    self.bloom_filter.encode(buf);
  }
}

crate::codec::impl_p2p!(GovSync);
