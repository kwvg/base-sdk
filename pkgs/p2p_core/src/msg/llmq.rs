//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! LLMQ messages.

use crate::codec::{codec_p2p, impl_p2p};
use crate::prelude::*;

use dash_primitives::{hash_impl, BlockHash};
use dash_types::codec::{self, BaseCodec, DecodeError, EncodeBuf};
use dash_types::type_id::TypeId;

/// Largest number of base block hashes in a `getqrinfo` message.
const MAX_BASE_BLOCK_HASHES: usize = 4096;

/// Recovered signature relay preference sent to a peer.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct QSendRecSigs {
  /// Whether the peer is to relay recovered signatures.
  pub send: bool,
}

codec_p2p!(QSendRecSigs { send });

/// Requests the quorum rotation info for a block.
#[derive(Clone, Debug, Eq, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct GetQrInfo {
  /// Blocks whose masternode lists the requester holds. A peer rejects more
  /// than 4096 hashes.
  pub base_block_hashes: Vec<BlockHash>,
  /// Block to build the rotation info at.
  pub block_request_hash: BlockHash,
  /// Whether to include the cycle four intervals back.
  pub extra_share: bool,
}

impl_p2p!(GetQrInfo);

impl BaseCodec for GetQrInfo {
  fn decode(data: &mut &[u8]) -> Result<Self, DecodeError> {
    Ok(Self {
      base_block_hashes: codec::decode_vec_limited(data, MAX_BASE_BLOCK_HASHES)?,
      block_request_hash: BlockHash::decode(data)?,
      extra_share: bool::decode(data)?,
    })
  }

  fn encode(&self, buf: &mut impl EncodeBuf) {
    self.base_block_hashes.encode(buf);
    self.block_request_hash.encode(buf);
    self.extra_share.encode(buf);
  }
}

hash_impl!(GetQrInfo);

#[cfg(test)]
mod tests {
  use super::{GetQrInfo, QSendRecSigs, MAX_BASE_BLOCK_HASHES};
  use crate::prelude::*;
  use crate::{CommandString, P2pDecodeError, P2pMsg};

  use dash_primitives::BlockHash;
  use dash_types::Numeric;
  use rstest::rstest;

  #[rstest]
  #[case::zero(0x00, false)]
  #[case::one(0x01, true)]
  #[case::other(0x02, true)]
  fn decodes_the_flag_byte(#[case] byte: u8, #[case] send: bool) {
    assert_eq!(
      P2pMsg::decode_payload(&CommandString::QSENDRECSIGS, &[byte]),
      Ok(P2pMsg::QSendRecSigs(QSendRecSigs { send }))
    );
  }

  #[rstest]
  #[case::off(false, 0x00)]
  #[case::on(true, 0x01)]
  fn encodes_one_byte(#[case] send: bool, #[case] byte: u8) {
    let mut buf = alloc::vec::Vec::new();
    P2pMsg::QSendRecSigs(QSendRecSigs { send }).encode_payload(&mut buf);
    assert_eq!(buf, [byte]);
  }

  #[rstest]
  fn rejects_an_empty_payload() {
    assert!(matches!(
      P2pMsg::decode_payload(&CommandString::QSENDRECSIGS, &[]),
      Err(P2pDecodeError::Consensus(_))
    ));
  }

  fn getqrinfo(count: usize) -> GetQrInfo {
    GetQrInfo {
      base_block_hashes: vec![BlockHash::from_lendian([0x11; 32]); count],
      block_request_hash: BlockHash::from_lendian([0x22; 32]),
      extra_share: true,
    }
  }

  #[rstest]
  fn getqrinfo_wire_is_bases_request_hash_and_flag() {
    let mut expected = vec![0x01];
    expected.extend([0x11; 32]);
    expected.extend([0x22; 32]);
    expected.push(0x01);
    let mut buf = Vec::new();
    P2pMsg::GetQrInfo(getqrinfo(1)).encode_payload(&mut buf);
    assert_eq!(buf, expected);
    assert_eq!(
      P2pMsg::decode_payload(&CommandString::GETQRINFO, &expected),
      Ok(P2pMsg::GetQrInfo(getqrinfo(1)))
    );
  }

  #[rstest]
  #[case::empty(0, true)]
  #[case::at_limit(MAX_BASE_BLOCK_HASHES, true)]
  #[case::past_limit(MAX_BASE_BLOCK_HASHES + 1, false)]
  fn getqrinfo_carries_at_most_4096_base_hashes(#[case] count: usize, #[case] accepted: bool) {
    let mut payload = Vec::new();
    P2pMsg::GetQrInfo(getqrinfo(count)).encode_payload(&mut payload);
    let decoded = P2pMsg::decode_payload(&CommandString::GETQRINFO, &payload);
    if accepted {
      assert_eq!(decoded, Ok(P2pMsg::GetQrInfo(getqrinfo(count))));
    } else {
      assert!(matches!(decoded, Err(P2pDecodeError::Consensus(_))));
    }
  }

  #[rstest]
  fn getqrinfo_rejects_trailing_bytes() {
    let mut payload = Vec::new();
    P2pMsg::GetQrInfo(getqrinfo(1)).encode_payload(&mut payload);
    payload.push(0);
    assert!(matches!(
      P2pMsg::decode_payload(&CommandString::GETQRINFO, &payload),
      Err(P2pDecodeError::Consensus(_))
    ));
  }
}
