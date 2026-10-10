//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! LLMQ messages.

use crate::codec::codec_p2p;

use dash_types::type_id::TypeId;

/// Recovered signature relay preference sent to a peer.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct QSendRecSigs {
  /// Whether the peer is to relay recovered signatures.
  pub send: bool,
}

codec_p2p!(QSendRecSigs { send });

#[cfg(test)]
mod tests {
  use super::QSendRecSigs;
  use crate::{CommandString, P2pDecodeError, P2pMsg};

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
}
