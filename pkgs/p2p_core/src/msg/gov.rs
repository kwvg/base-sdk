//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Governance sync request message.

use super::BloomFilter;
use crate::codec::codec_p2p;

use dash_num::Hash256;
use dash_types::type_id::TypeId;

/// Requests governance objects and votes from a peer.
///
/// When `hash` is zero, the peer responds with all governance
/// objects. When non-zero, it responds with votes for that
/// specific object.
#[derive(Clone, Debug, Eq, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct GovSync {
  /// Object hash (zero for full sync).
  pub hash: Hash256,
  /// Filter of the votes the sender already holds.
  pub bloom_filter: BloomFilter,
}

codec_p2p!(GovSync { hash, bloom_filter });

#[cfg(test)]
mod tests {
  use super::{BloomFilter, GovSync};
  use crate::prelude::*;
  use crate::{CommandString, P2pDecodeError, P2pMsg};

  use dash_num::Hash256;
  use dash_types::Numeric;
  use rstest::rstest;

  /// Full sync request as `SyncManager` sends it, with a null hash and a
  /// default `CBloomFilter`.
  const FULL_SYNC: [u8; 42] = [0; 42];

  #[rstest]
  fn full_sync_request_round_trips() {
    let msg = P2pMsg::GovSync(GovSync {
      hash: Hash256::default(),
      bloom_filter: BloomFilter::default(),
    });
    assert_eq!(
      P2pMsg::decode_payload(&CommandString::GOVSYNC, &FULL_SYNC),
      Ok(msg.clone())
    );
    let mut buf = Vec::new();
    msg.encode_payload(&mut buf);
    assert_eq!(buf, FULL_SYNC);
  }

  #[rstest]
  fn vote_sync_request_carries_the_whole_filter() {
    let raw = [&[0x11; 32][..], &[2, 0xaa, 0xbb, 5, 0, 0, 0, 0x3f, 0x42, 0x0f, 0, 1]].concat();
    let want = GovSync {
      hash: Hash256::from_lendian([0x11; 32]),
      bloom_filter: BloomFilter {
        data: vec![0xaa, 0xbb],
        hash_funcs: 5,
        tweak: 999_999,
        flags: 1,
      },
    };
    assert_eq!(
      P2pMsg::decode_payload(&CommandString::GOVSYNC, &raw),
      Ok(P2pMsg::GovSync(want))
    );
  }

  #[rstest]
  #[case::truncated(&FULL_SYNC[..41])]
  #[case::trailing(&[&FULL_SYNC[..], &[0]].concat())]
  fn rejects_a_misframed_filter(#[case] raw: &[u8]) {
    assert!(matches!(
      P2pMsg::decode_payload(&CommandString::GOVSYNC, raw),
      Err(P2pDecodeError::Consensus(_))
    ));
  }
}
