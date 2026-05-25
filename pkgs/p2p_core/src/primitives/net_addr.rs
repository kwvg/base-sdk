//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Network address types for P2P messages.

use crate::encode::MAX_P2P_PAYLOAD;
use crate::prelude::*;
use crate::primitives::service_flags::ServiceFlags;

use bitcoin_consensus_encoding as encoding;
use dash_primitives::wire;
use dash_primitives::CService;
use dash_primitives::NetworkType;
use dash_types::codec::{self, Codec, DecodeError, NumCodec};
use dash_types::{BufferDecoder, VecEncoder};

use core::fmt;

/// Network address with service flags (used inside the version message).
///
/// Wire format: `u64 services` + `[u8; 16] addr` + `u16 BE port`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct NetAddr {
  /// Advertised services.
  pub services: ServiceFlags,
  /// IPv4-mapped IPv6 address + port.
  pub addr: CService,
}

impl Codec for NetAddr {
  fn decode(data: &mut &[u8]) -> Result<Self, DecodeError> {
    let services = ServiceFlags(codec::read_u64_le(data)?);
    let addr = wire::read_cservice(data)?;
    Ok(Self { services, addr })
  }

  fn encode(&self, buf: &mut Vec<u8>) {
    buf.extend_from_slice(&self.services.0.to_le_bytes());
    buf.extend_from_slice(&self.addr.addr);
    buf.extend_from_slice(&self.addr.port.to_be_bytes());
  }
}

impl encoding::Encodable for NetAddr {
  type Encoder<'e> = VecEncoder;
  fn encoder(&self) -> Self::Encoder<'_> {
    let mut buf = Vec::new();
    Codec::encode(self, &mut buf);
    VecEncoder::new(buf)
  }
}

impl encoding::Decodable for NetAddr {
  type Decoder = BufferDecoder<NetAddr, DecodeError>;
  fn decoder() -> Self::Decoder {
    BufferDecoder::new(<Self as Codec>::decode, MAX_P2P_PAYLOAD)
  }
}

impl fmt::Display for NetAddr {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "{:?} ({})", self.addr, self.services)
  }
}

/// Timestamped v1 address entry used in `addr` messages.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct TimestampedAddr {
  /// Seconds since Unix epoch.
  pub time: u32,
  /// Advertised services.
  pub services: ServiceFlags,
  /// IPv4-mapped IPv6 address + port.
  pub addr: CService,
}

impl Codec for TimestampedAddr {
  fn decode(data: &mut &[u8]) -> Result<Self, DecodeError> {
    let time = codec::read_u32_le(data)?;
    let services = ServiceFlags(codec::read_u64_le(data)?);
    let addr = wire::read_cservice(data)?;
    Ok(Self { time, services, addr })
  }

  fn encode(&self, buf: &mut Vec<u8>) {
    buf.extend_from_slice(&self.time.to_le_bytes());
    buf.extend_from_slice(&self.services.0.to_le_bytes());
    buf.extend_from_slice(&self.addr.addr);
    buf.extend_from_slice(&self.addr.port.to_be_bytes());
  }
}

impl encoding::Encodable for TimestampedAddr {
  type Encoder<'e> = VecEncoder;
  fn encoder(&self) -> Self::Encoder<'_> {
    let mut buf = Vec::new();
    Codec::encode(self, &mut buf);
    VecEncoder::new(buf)
  }
}

impl encoding::Decodable for TimestampedAddr {
  type Decoder = BufferDecoder<TimestampedAddr, DecodeError>;
  fn decoder() -> Self::Decoder {
    BufferDecoder::new(<Self as Codec>::decode, MAX_P2P_PAYLOAD)
  }
}

/// BIP155 v2 network address supporting multiple transport types.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct AddrV2 {
  /// Network transport type.
  pub network: NetworkType,
  /// Raw address bytes (length depends on network type).
  pub addr: Vec<u8>,
}

impl AddrV2 {
  /// Expected byte length for a given network type, if known.
  const fn expected_len(net: NetworkType) -> Option<usize> {
    match net {
      NetworkType::Ipv4 => Some(4),
      NetworkType::Ipv6 => Some(16),
      NetworkType::TorV3 => Some(32),
      NetworkType::I2P => Some(32),
      NetworkType::Cjdns => Some(16),
      NetworkType::Unknown(_) => None,
    }
  }
}

impl Codec for AddrV2 {
  fn decode(data: &mut &[u8]) -> Result<Self, DecodeError> {
    let net_byte = codec::read_u8(data)?;
    let network = NetworkType::from_base(net_byte);
    let len = codec::read_compact_size(data, 512)?;
    let addr = codec::read_bytes(data, len)?.to_vec();
    if let Some(expected) = Self::expected_len(network) {
      if addr.len() != expected {
        return Err(DecodeError::Eof {
          needed: expected,
          remaining: addr.len(),
        });
      }
    }
    Ok(Self { network, addr })
  }

  fn encode(&self, buf: &mut Vec<u8>) {
    buf.push(self.network.to_base());
    codec::write_compact_size(self.addr.len(), buf);
    buf.extend_from_slice(&self.addr);
  }
}

impl encoding::Encodable for AddrV2 {
  type Encoder<'e> = VecEncoder;
  fn encoder(&self) -> Self::Encoder<'_> {
    let mut buf = Vec::new();
    Codec::encode(self, &mut buf);
    VecEncoder::new(buf)
  }
}

impl encoding::Decodable for AddrV2 {
  type Decoder = BufferDecoder<AddrV2, DecodeError>;
  fn decoder() -> Self::Decoder {
    BufferDecoder::new(<Self as Codec>::decode, MAX_P2P_PAYLOAD)
  }
}

/// BIP155 timestamped v2 address entry used in `addrv2` messages.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct AddrV2Entry {
  /// Seconds since Unix epoch.
  pub time: u32,
  /// Advertised services (CompactSize-encoded on wire).
  pub services: ServiceFlags,
  /// Network address.
  pub addr: AddrV2,
  /// Port number (big-endian on wire).
  pub port: u16,
}

impl Codec for AddrV2Entry {
  fn decode(data: &mut &[u8]) -> Result<Self, DecodeError> {
    let time = codec::read_u32_le(data)?;
    let services = ServiceFlags(codec::read_compact_u64(data)?);
    let net_byte = codec::read_u8(data)?;
    let network = NetworkType::from_base(net_byte);
    let len = codec::read_compact_size(data, 512)?;
    let addr_bytes = codec::read_bytes(data, len)?.to_vec();
    if let Some(expected) = AddrV2::expected_len(network) {
      if addr_bytes.len() != expected {
        return Err(DecodeError::Eof {
          needed: expected,
          remaining: addr_bytes.len(),
        });
      }
    }
    let addr = AddrV2 {
      network,
      addr: addr_bytes,
    };
    let port = codec::read_u16_be(data)?;
    Ok(Self {
      time,
      services,
      addr,
      port,
    })
  }

  fn encode(&self, buf: &mut Vec<u8>) {
    buf.extend_from_slice(&self.time.to_le_bytes());
    codec::write_compact_size(self.services.0 as usize, buf);
    buf.push(self.addr.network.to_base());
    codec::write_compact_size(self.addr.addr.len(), buf);
    buf.extend_from_slice(&self.addr.addr);
    buf.extend_from_slice(&self.port.to_be_bytes());
  }
}

impl encoding::Encodable for AddrV2Entry {
  type Encoder<'e> = VecEncoder;
  fn encoder(&self) -> Self::Encoder<'_> {
    let mut buf = Vec::new();
    Codec::encode(self, &mut buf);
    VecEncoder::new(buf)
  }
}

impl encoding::Decodable for AddrV2Entry {
  type Decoder = BufferDecoder<AddrV2Entry, DecodeError>;
  fn decoder() -> Self::Decoder {
    BufferDecoder::new(<Self as Codec>::decode, MAX_P2P_PAYLOAD)
  }
}

impl fmt::Display for AddrV2Entry {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "{:?}:{}", self.addr.network, self.port)
  }
}
