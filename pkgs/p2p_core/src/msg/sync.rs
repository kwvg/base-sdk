//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Sync status count message.

use crate::codec::codec_p2p;

use dash_types::make_num;
use dash_types::type_id::TypeId;

make_num! {
  /// Kind of item a sync status count reports.
  SyncItemId, i32, 4
}

impl SyncItemId {
  /// Governance objects.
  pub const GOVERNANCE_OBJECTS: Self = Self(10);
  /// Governance object votes.
  pub const GOVERNANCE_VOTES: Self = Self(11);
}

/// Number of items a peer is about to announce in reply to `govsync`.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub struct SyncStatusCount {
  /// Kind of the announced items.
  pub item_id: SyncItemId,
  /// Number of announced items.
  pub count: i32,
}

codec_p2p!(SyncStatusCount { item_id, count });

#[cfg(test)]
mod tests {
  use super::{SyncItemId, SyncStatusCount};
  use crate::prelude::*;
  use crate::{CommandString, P2pDecodeError, P2pMsg};

  use rstest::rstest;

  #[rstest]
  #[case::objects(SyncItemId::GOVERNANCE_OBJECTS, 3, [10, 0, 0, 0, 3, 0, 0, 0])]
  #[case::votes(SyncItemId::GOVERNANCE_VOTES, 0x0102, [11, 0, 0, 0, 2, 1, 0, 0])]
  #[case::unknown(SyncItemId(-1), -2, [0xff, 0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xff])]
  fn round_trips(#[case] item_id: SyncItemId, #[case] count: i32, #[case] raw: [u8; 8]) {
    let msg = P2pMsg::Ssc(SyncStatusCount { item_id, count });
    assert_eq!(P2pMsg::decode_payload(&CommandString::SSC, &raw), Ok(msg.clone()));
    let mut buf = Vec::new();
    msg.encode_payload(&mut buf);
    assert_eq!(buf, raw);
  }

  #[rstest]
  fn rejects_a_truncated_count() {
    assert!(matches!(
      P2pMsg::decode_payload(&CommandString::SSC, &[10, 0, 0, 0, 3, 0, 0]),
      Err(P2pDecodeError::Consensus(_))
    ));
  }
}
