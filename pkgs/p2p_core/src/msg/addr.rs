//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Address messages: addr, addrv2 (getaddr and sendaddrv2 are empty).

use crate::encode::MAX_P2P_PAYLOAD;
use crate::error::P2pDecodeError;
use crate::prelude::*;
use crate::primitives::net_addr::{AddrV2Entry, TimestampedAddr};
use crate::primitives::service_flags::ServiceFlags;

use bitcoin_consensus_encoding as encoding;
use dash_primitives::codec::{BufferDecoder, VecEncoder};
use dash_primitives::wire;
use dash_types::codec;

/// Maximum addresses per message.
const MAX_ADDR: usize = 1_000;

/// V1 address announcement carrying timestamped addresses.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct Addr {
  /// Timestamped v1 address entries.
  pub addrs: Vec<TimestampedAddr>,
}

impl Addr {
  fn decode_from_slice(data: &[u8]) -> Result<Self, P2pDecodeError> {
    let sl = &mut &data[..];
    let count = codec::read_compact_size(sl, MAX_ADDR)?;
    let mut addrs = Vec::with_capacity(count);
    for _ in 0..count {
      let time = codec::read_u32_le(sl)?;
      let services = ServiceFlags(codec::read_u64_le(sl)?);
      let addr = wire::read_cservice(sl)?;
      addrs.push(TimestampedAddr { time, services, addr });
    }
    Ok(Self { addrs })
  }

  fn encode_to_vec(&self) -> Vec<u8> {
    let mut buf = Vec::new();
    codec::write_compact_size(self.addrs.len(), &mut buf);
    for a in &self.addrs {
      buf.extend_from_slice(&a.time.to_le_bytes());
      buf.extend_from_slice(&a.services.0.to_le_bytes());
      buf.extend_from_slice(&a.addr.addr);
      buf.extend_from_slice(&a.addr.port.to_be_bytes());
    }
    buf
  }
}

impl encoding::Encodable for Addr {
  type Encoder<'e> = VecEncoder;
  fn encoder(&self) -> Self::Encoder<'_> {
    VecEncoder::new(self.encode_to_vec())
  }
}

impl encoding::Decodable for Addr {
  type Decoder = BufferDecoder<Addr, P2pDecodeError>;
  fn decoder() -> Self::Decoder {
    BufferDecoder::new(Addr::decode_from_slice, MAX_P2P_PAYLOAD)
  }
}

/// BIP155 v2 address announcement.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct AddrV2Msg {
  /// BIP155 address entries.
  pub addrs: Vec<AddrV2Entry>,
}

impl AddrV2Msg {
  fn decode_from_slice(data: &[u8]) -> Result<Self, P2pDecodeError> {
    let sl = &mut &data[..];
    let count = codec::read_compact_size(sl, MAX_ADDR)?;
    let mut addrs = Vec::with_capacity(count);
    for _ in 0..count {
      addrs.push(AddrV2Entry::decode_from_wire(sl)?);
    }
    Ok(Self { addrs })
  }

  fn encode_to_vec(&self) -> Vec<u8> {
    let mut buf = Vec::new();
    codec::write_compact_size(self.addrs.len(), &mut buf);
    for a in &self.addrs {
      let entry_bytes = encoding::encode_to_vec(a);
      buf.extend_from_slice(&entry_bytes);
    }
    buf
  }
}

impl encoding::Encodable for AddrV2Msg {
  type Encoder<'e> = VecEncoder;
  fn encoder(&self) -> Self::Encoder<'_> {
    VecEncoder::new(self.encode_to_vec())
  }
}

impl encoding::Decodable for AddrV2Msg {
  type Decoder = BufferDecoder<AddrV2Msg, P2pDecodeError>;
  fn decoder() -> Self::Decoder {
    BufferDecoder::new(AddrV2Msg::decode_from_slice, MAX_P2P_PAYLOAD)
  }
}
