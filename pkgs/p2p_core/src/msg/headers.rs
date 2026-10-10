//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Standard header messages.

use crate::codec::{codec_p2p, impl_p2p};
use crate::prelude::*;
use crate::version::ProtocolVersion;

use dash_primitives::{hash_impl, BlockHash, BlockHeader, MerkleRoot};
use dash_types::codec::{BaseCodec, DecodeError, EncodeBuf};
use dash_types::type_id::{TypeId, Unencodable};
use dash_types::{Checkable, CompactSize, Hashable};

use core::fmt;

/// Maximum headers per message.
const MAX_HEADERS: usize = 2_000;

/// A header in a batch does not build on the header before it.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Unencodable)]
pub struct NonContinuousHeaders {
  /// Position of the first header whose `prev_hash` breaks the chain.
  pub index: usize,
}

impl fmt::Display for NonContinuousHeaders {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "non-continuous headers sequence at index {}", self.index)
  }
}

/// Finds the first header in `headers` that does not build on its predecessor.
pub(crate) fn check_chain(headers: &[BlockHeader]) -> Option<NonContinuousHeaders> {
  headers
    .windows(2)
    .position(|pair| pair[1].prev_hash != pair[0].hash())
    .map(|position| NonContinuousHeaders { index: position + 1 })
}

/// Requests block headers starting from a locator.
#[derive(Clone, Debug, Eq, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct GetHeaders {
  /// Protocol version.
  pub version: ProtocolVersion,
  /// Block locator hashes (newest first).
  pub locator_hashes: Vec<BlockHash>,
  /// Stop hash (zero to get as many as possible).
  pub hash_stop: BlockHash,
}

codec_p2p!(GetHeaders {
  version,
  locator_hashes,
  hash_stop
});

/// Response carrying block headers.
///
/// Each header is followed by a CompactSize transaction count
/// (always zero, since full blocks are not included).
#[derive(Clone, Debug, Eq, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct Headers {
  /// Block headers.
  pub headers: Vec<BlockHeader>,
}

impl_p2p!(Headers);

impl BaseCodec for Headers {
  fn decode(data: &mut &[u8]) -> Result<Self, DecodeError> {
    let count = CompactSize::decode(data)?.into_len(MAX_HEADERS)?;
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
      CompactSize::decode(data)?.into_len(0)?;
    }
    Ok(Self { headers })
  }

  fn encode(&self, buf: &mut impl EncodeBuf) {
    CompactSize::from(self.headers.len()).encode(buf);
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

impl Checkable for Headers {
  type Error = NonContinuousHeaders;

  fn check(&self) -> Option<Self::Error> {
    check_chain(&self.headers)
  }
}

hash_impl!(Headers);

#[cfg(test)]
mod tests {
  use super::*;

  use rstest::rstest;

  fn chain(len: usize) -> Vec<BlockHeader> {
    let mut headers: Vec<BlockHeader> = Vec::with_capacity(len);
    for nonce in 0..len as u32 {
      let prev_hash = headers.last().map(|h| h.hash()).unwrap_or_default();
      headers.push(BlockHeader {
        prev_hash,
        nonce,
        ..BlockHeader::default()
      });
    }
    headers
  }

  #[rstest]
  #[case::empty(0)]
  #[case::single(1)]
  #[case::chained(3)]
  fn accepts_a_chain(#[case] len: usize) {
    assert_eq!(Headers { headers: chain(len) }.check(), None);
  }

  #[rstest]
  #[case::second(1)]
  #[case::last(2)]
  fn rejects_a_broken_link(#[case] index: usize) {
    let mut headers = chain(3);
    headers[index].prev_hash = BlockHash::default();
    assert_eq!(Headers { headers }.check(), Some(NonContinuousHeaders { index }));
  }
}
