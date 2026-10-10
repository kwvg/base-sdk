//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Address messages.

use super::version::ServiceFlags;
use crate::codec::{codec_p2p, impl_p2p};
use crate::error::{check_count, TooManyEntries};
use crate::prelude::*;

use dash_primitives::{hash_impl, AddrV2, ServiceV1};
use dash_types::codec::{self, BaseCodec, DecodeError, EncodeBuf};
use dash_types::type_id::TypeId;
use dash_types::{Checkable, CompactSize, Numeric};

use core::fmt;

/// Largest number of entries in an `addr` or `addrv2` message.
const MAX_ADDR_TO_SEND: usize = 1_000;

/// V1 address announcement carrying timestamped addresses.
#[derive(Clone, Debug, Eq, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct Addr {
  /// Timestamped v1 address entries.
  pub addrs: Vec<TimestampedAddr>,
}

codec_p2p!(Addr { addrs });

impl Checkable for Addr {
  type Error = TooManyEntries;

  fn check(&self) -> Option<Self::Error> {
    check_count(self.addrs.len(), MAX_ADDR_TO_SEND)
  }
}

/// BIP155 timestamped v2 address entry used in `addrv2` messages.
#[derive(Clone, Debug, Eq, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct AddrV2Entry {
  /// Seconds since Unix epoch.
  pub time: u32,
  /// Advertised services.
  pub services: ServiceFlags,
  /// Network address.
  pub addr: AddrV2,
  /// Port number.
  pub port: u16,
}

impl BaseCodec for AddrV2Entry {
  fn decode(data: &mut &[u8]) -> Result<Self, DecodeError> {
    let time = u32::decode(data)?;
    let services = ServiceFlags(CompactSize::decode(data)?.to_base());
    let addr = AddrV2::decode(data)?;
    let port = codec::read_u16_be(data)?;
    Ok(Self {
      time,
      services,
      addr,
      port,
    })
  }

  fn encode(&self, buf: &mut impl EncodeBuf) {
    self.time.encode(buf);
    CompactSize::from(self.services.0).encode(buf);
    self.addr.encode(buf);
    buf.extend_from_slice(&self.port.to_be_bytes());
  }
}

impl_p2p!(AddrV2Entry);

hash_impl!(AddrV2Entry);

impl fmt::Display for AddrV2Entry {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "{:?}:{}", self.addr.network(), self.port)
  }
}

/// BIP155 v2 address announcement.
#[derive(Clone, Debug, Eq, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct AddrV2Msg {
  /// BIP155 address entries.
  pub addrs: Vec<AddrV2Entry>,
}

codec_p2p!(AddrV2Msg { addrs });

impl Checkable for AddrV2Msg {
  type Error = TooManyEntries;

  fn check(&self) -> Option<Self::Error> {
    check_count(self.addrs.len(), MAX_ADDR_TO_SEND)
  }
}

/// Timestamped v1 address entry used in `addr` messages.
#[derive(Clone, Debug, Eq, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct TimestampedAddr {
  /// Seconds since Unix epoch.
  pub time: u32,
  /// Advertised services.
  pub services: ServiceFlags,
  /// Network address.
  pub addr: ServiceV1,
}

codec_p2p!(TimestampedAddr { time, services, addr });

#[cfg(test)]
mod tests {
  use super::*;

  use dash_primitives::AddrV1;
  use rstest::rstest;

  #[rstest]
  #[case::empty(0, None)]
  #[case::at_limit(MAX_ADDR_TO_SEND, None)]
  #[case::past_limit(MAX_ADDR_TO_SEND + 1, Some(TooManyEntries { count: MAX_ADDR_TO_SEND + 1, limit: MAX_ADDR_TO_SEND }))]
  fn addr_and_addrv2_carry_at_most_1000_entries(#[case] count: usize, #[case] expected: Option<TooManyEntries>) {
    let v1 = TimestampedAddr {
      time: 0,
      services: ServiceFlags::NONE,
      addr: ServiceV1 {
        addr: AddrV1::default(),
        port: 9999,
      },
    };
    let v2 = AddrV2Entry {
      time: 0,
      services: ServiceFlags::NONE,
      addr: AddrV2::Ipv4([10, 0, 0, 1]),
      port: 9999,
    };
    assert_eq!(Addr { addrs: vec![v1; count] }.check(), expected);
    assert_eq!(AddrV2Msg { addrs: vec![v2; count] }.check(), expected);
  }
}
