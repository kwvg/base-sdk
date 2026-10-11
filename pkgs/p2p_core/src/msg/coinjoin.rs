//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! CoinJoin messages.

use crate::codec::{codec_p2p, impl_p2p};
use crate::macros::VersionedPayload;
use crate::prelude::*;
use crate::{P2pDecodeError, ProtocolVersion};

use dash_primitives::{hash_impl, Transaction};
use dash_types::codec::{BaseCodec, DecodeError, EncodeBuf};
use dash_types::type_id::TypeId;

/// CoinJoin queue relay preference sent to a peer.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct SendDsq {
  /// Whether the peer is to relay CoinJoin queue messages.
  pub send: bool,
}

codec_p2p!(SendDsq { send });

/// Request to join a CoinJoin mixing session.
#[derive(Clone, Debug, Eq, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct CoinJoinAccept {
  /// Denomination of the session.
  pub denomination: i32,
  /// Collateral transaction that the masternode may broadcast as a penalty.
  pub collateral: Transaction,
  /// Rebalance direction, bit 0 for promotion and bit 1 for demotion. Peers
  /// below protocol 70241 neither send nor receive it, so it decodes as 0.
  pub flags: u8,
}

impl_p2p!(CoinJoinAccept);

impl BaseCodec for CoinJoinAccept {
  fn decode(data: &mut &[u8]) -> Result<Self, DecodeError> {
    Self::decode_at(data, ProtocolVersion::CURRENT)
  }

  fn encode(&self, buf: &mut impl EncodeBuf) {
    self.encode_at(buf, ProtocolVersion::CURRENT);
  }
}

hash_impl!(CoinJoinAccept);

impl CoinJoinAccept {
  /// Reads the request as sent at protocol `version`.
  fn decode_at(data: &mut &[u8], version: ProtocolVersion) -> Result<Self, DecodeError> {
    let denomination = i32::decode(data)?;
    let collateral = Transaction::decode(data)?;
    let flags = if version >= ProtocolVersion::COINJOIN_REBALANCE {
      u8::decode(data)?
    } else {
      0
    };
    Ok(Self {
      denomination,
      collateral,
      flags,
    })
  }

  /// Writes the request as sent at protocol `version`.
  fn encode_at(&self, buf: &mut impl EncodeBuf, version: ProtocolVersion) {
    self.denomination.encode(buf);
    self.collateral.encode(buf);
    if version >= ProtocolVersion::COINJOIN_REBALANCE {
      self.flags.encode(buf);
    }
  }
}

impl VersionedPayload for CoinJoinAccept {
  fn decode_versioned(payload: &[u8], version: ProtocolVersion) -> Result<Self, P2pDecodeError> {
    let mut data = payload;
    let accept = Self::decode_at(&mut data, version)?;
    if !data.is_empty() {
      return Err(DecodeError::TrailingBytes { remaining: data.len() }.into());
    }
    Ok(accept)
  }

  fn encode_versioned(&self, buf: &mut Vec<u8>, version: ProtocolVersion) {
    self.encode_at(buf, version);
  }
}

#[cfg(test)]
mod tests {
  use super::{CoinJoinAccept, SendDsq};
  use crate::prelude::*;
  use crate::{CommandString, P2pDecodeError, P2pMsg, ProtocolVersion};

  use dash_primitives::{Transaction, TxType};
  use dash_types::codec::BaseCodec;
  use rstest::rstest;

  #[rstest]
  #[case::zero(0x00, false)]
  #[case::one(0x01, true)]
  #[case::other(0x02, true)]
  fn decodes_the_flag_byte(#[case] byte: u8, #[case] send: bool) {
    assert_eq!(
      P2pMsg::decode_payload(&CommandString::SENDDSQ, &[byte]),
      Ok(P2pMsg::SendDsq(SendDsq { send }))
    );
  }

  #[rstest]
  #[case::off(false, 0x00)]
  #[case::on(true, 0x01)]
  fn encodes_one_byte(#[case] send: bool, #[case] byte: u8) {
    let mut buf = alloc::vec::Vec::new();
    P2pMsg::SendDsq(SendDsq { send }).encode_payload(&mut buf);
    assert_eq!(buf, [byte]);
  }

  #[rstest]
  fn rejects_an_empty_payload() {
    assert!(matches!(
      P2pMsg::decode_payload(&CommandString::SENDDSQ, &[]),
      Err(P2pDecodeError::Consensus(_))
    ));
  }

  fn collateral() -> Transaction {
    Transaction {
      version: 3,
      tx_type: TxType::Spend,
      inputs: Vec::new(),
      outputs: Vec::new(),
      lock_time: 7,
      extra_payload: Vec::new(),
    }
  }

  fn dsa(flags: u8) -> CoinJoinAccept {
    CoinJoinAccept {
      denomination: 2,
      collateral: collateral(),
      flags,
    }
  }

  fn dsa_payload(flags: Option<u8>) -> Vec<u8> {
    let mut payload = vec![0x02, 0x00, 0x00, 0x00];
    collateral().encode(&mut payload);
    payload.extend(flags);
    payload
  }

  #[rstest]
  #[case::below_rebalance(ProtocolVersion::PLATFORMBAN_V2_SHORT_ID, 0, None)]
  #[case::at_rebalance(ProtocolVersion::COINJOIN_REBALANCE, 1, Some(1))]
  #[case::both_directions(ProtocolVersion::ASSET_UNLOCK_INV, 3, Some(3))]
  fn dsa_carries_flags_from_70241(#[case] version: ProtocolVersion, #[case] flags: u8, #[case] wire: Option<u8>) {
    let payload = dsa_payload(wire);
    let mut buf = Vec::new();
    P2pMsg::Dsa(dsa(flags)).encode_payload_with_version(&mut buf, version);
    assert_eq!(buf, payload);
    assert_eq!(
      P2pMsg::decode_payload_with_version(&CommandString::DSA, &payload, version),
      Ok(P2pMsg::Dsa(dsa(flags)))
    );
  }

  #[rstest]
  fn dsa_drops_flags_below_70241() {
    let mut buf = Vec::new();
    P2pMsg::Dsa(dsa(2)).encode_payload_with_version(&mut buf, ProtocolVersion::PLATFORMBAN_V2_SHORT_ID);
    assert_eq!(buf, dsa_payload(None));
  }

  #[rstest]
  #[case::flags_below_rebalance(ProtocolVersion::PLATFORMBAN_V2_SHORT_ID, dsa_payload(Some(0)))]
  #[case::no_flags_at_rebalance(ProtocolVersion::COINJOIN_REBALANCE, dsa_payload(None))]
  #[case::trailing_at_rebalance(ProtocolVersion::COINJOIN_REBALANCE, [dsa_payload(Some(0)), vec![0]].concat())]
  fn dsa_rejects_a_payload_of_another_layout(#[case] version: ProtocolVersion, #[case] payload: Vec<u8>) {
    assert!(matches!(
      P2pMsg::decode_payload_with_version(&CommandString::DSA, &payload, version),
      Err(P2pDecodeError::Consensus(_))
    ));
  }
}
