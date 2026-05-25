//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Version handshake message (Dash-extended).

use crate::encode::{encode_compact_size, BufferDecoder, VecEncoder, WireDecodeError, MAX_P2P_PAYLOAD};
use crate::prelude::*;
use crate::primitives::net_addr::NetAddr;
use crate::primitives::protocol_version::ProtocolVersion;
use crate::primitives::service_flags::ServiceFlags;
use crate::primitives::user_agent::UserAgent;

use bitcoin_consensus_encoding as encoding;
use dash_num::Hash256;
use dash_primitives::wire;

/// Maximum user agent length in bytes.
const MAX_USER_AGENT: usize = 256;

/// The `version` message initiates the P2P handshake.
///
/// Dash extends the Bitcoin version message with two additional
/// fields for masternode authentication.
#[derive(Debug, Clone, PartialEq, Eq)]
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

impl Version {
  fn decode_from_slice(data: &[u8]) -> Result<Self, WireDecodeError> {
    let sl = &mut &data[..];
    let protocol_version = ProtocolVersion(wire::read_u32_le(sl)?);
    let services = ServiceFlags(wire::read_u64_le(sl)?);
    let timestamp = wire::read_i64_le(sl)?;
    // addr_recv: services(8) + addr(16) + port(2)
    let recv_services = ServiceFlags(wire::read_u64_le(sl)?);
    let recv_addr = wire::read_cservice(sl)?;
    let addr_recv = NetAddr {
      services: recv_services,
      addr: recv_addr,
    };
    // addr_send
    let send_services = ServiceFlags(wire::read_u64_le(sl)?);
    let send_addr = wire::read_cservice(sl)?;
    let addr_send = NetAddr {
      services: send_services,
      addr: send_addr,
    };
    let nonce = wire::read_u64_le(sl)?;
    // user agent
    let ua_len = wire::read_compact_size(sl, MAX_USER_AGENT)?;
    let ua_bytes = wire::read_bytes(sl, ua_len)?.to_vec();
    let user_agent = UserAgent::new(ua_bytes).map_err(|e| WireDecodeError(format!("{e}")))?;
    let start_height = wire::read_i32_le(sl)?;
    let relay = wire::read_bool(sl)?;
    let mnauth_challenge = Hash256::from_bytes(wire::read_array(sl)?);
    let mn_connection = wire::read_bool(sl)?;
    Ok(Self {
      protocol_version,
      services,
      timestamp,
      addr_recv,
      addr_send,
      nonce,
      user_agent,
      start_height,
      relay,
      mnauth_challenge,
      mn_connection,
    })
  }

  fn encode_to_vec(&self) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(&self.protocol_version.0.to_le_bytes());
    buf.extend_from_slice(&self.services.0.to_le_bytes());
    buf.extend_from_slice(&self.timestamp.to_le_bytes());
    // addr_recv
    buf.extend_from_slice(&self.addr_recv.services.0.to_le_bytes());
    buf.extend_from_slice(&self.addr_recv.addr.addr);
    buf.extend_from_slice(&self.addr_recv.addr.port.to_be_bytes());
    // addr_send
    buf.extend_from_slice(&self.addr_send.services.0.to_le_bytes());
    buf.extend_from_slice(&self.addr_send.addr.addr);
    buf.extend_from_slice(&self.addr_send.addr.port.to_be_bytes());
    buf.extend_from_slice(&self.nonce.to_le_bytes());
    // user agent
    encode_compact_size(self.user_agent.len(), &mut buf);
    buf.extend_from_slice(self.user_agent.as_bytes());
    buf.extend_from_slice(&self.start_height.to_le_bytes());
    buf.push(u8::from(self.relay));
    buf.extend_from_slice(&self.mnauth_challenge.to_bytes());
    buf.push(u8::from(self.mn_connection));
    buf
  }
}

impl encoding::Encodable for Version {
  type Encoder<'e> = VecEncoder;
  fn encoder(&self) -> Self::Encoder<'_> {
    VecEncoder::new(self.encode_to_vec())
  }
}

impl encoding::Decodable for Version {
  type Decoder = BufferDecoder<Version, WireDecodeError>;
  fn decoder() -> Self::Decoder {
    BufferDecoder::new(Version::decode_from_slice, MAX_P2P_PAYLOAD)
  }
}
