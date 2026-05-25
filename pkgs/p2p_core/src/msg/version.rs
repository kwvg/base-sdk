//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Version handshake message (Dash-extended).

use crate::prelude::*;
use crate::primitives::net_addr::NetAddr;
use crate::primitives::protocol_version::ProtocolVersion;
use crate::primitives::service_flags::ServiceFlags;
use crate::primitives::user_agent::UserAgent;

use dash_num::Hash256;
use dash_types::codec::{Codec, DecodeError};

/// The `version` message initiates the P2P handshake.
///
/// Dash extends the Bitcoin version message with two additional
/// fields for masternode authentication.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct Version {
  /// Sender's protocol version.
  pub protocol_version: ProtocolVersion,
  /// Sender's advertised services.
  pub services: ServiceFlags,
  /// Unix timestamp of the sender.
  pub timestamp: i64,
  /// Receiver's address as seen by the sender.
  pub addr_recv: NetAddr,
  /// Sender's own address.
  pub addr_send: NetAddr,
  /// Random nonce for connection deduplication.
  pub nonce: u64,
  /// User agent string.
  pub user_agent: UserAgent,
  /// Sender's best block height.
  pub start_height: i32,
  /// Whether the sender wants transaction relay.
  pub relay: bool,
  /// Dash: masternode authentication challenge.
  pub mnauth_challenge: Hash256,
  /// Dash: whether the sender identifies as a masternode.
  pub mn_connection: bool,
}

impl Codec for Version {
  fn decode(data: &mut &[u8]) -> Result<Self, DecodeError> {
    Ok(Self {
      protocol_version: ProtocolVersion(u32::decode(data)?),
      services: ServiceFlags(u64::decode(data)?),
      timestamp: i64::decode(data)?,
      addr_recv: NetAddr::decode(data)?,
      addr_send: NetAddr::decode(data)?,
      nonce: u64::decode(data)?,
      user_agent: UserAgent::decode(data)?,
      start_height: i32::decode(data)?,
      relay: bool::decode(data)?,
      mnauth_challenge: Hash256::decode(data)?,
      mn_connection: bool::decode(data)?,
    })
  }

  fn encode(&self, buf: &mut Vec<u8>) {
    self.protocol_version.0.encode(buf);
    self.services.0.encode(buf);
    self.timestamp.encode(buf);
    self.addr_recv.encode(buf);
    self.addr_send.encode(buf);
    self.nonce.encode(buf);
    self.user_agent.encode(buf);
    self.start_height.encode(buf);
    self.relay.encode(buf);
    self.mnauth_challenge.encode(buf);
    self.mn_connection.encode(buf);
  }
}

crate::codec::impl_p2p!(Version);
