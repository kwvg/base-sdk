//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Address messages: addr, addrv2 (getaddr and sendaddrv2 are empty).

use crate::prelude::*;
use crate::primitives::net_addr::{AddrV2Entry, TimestampedAddr};

use dash_types::codec::{self, Codec, DecodeError};

/// Maximum addresses per message.
const MAX_ADDR: usize = 1_000;

/// V1 address announcement carrying timestamped addresses.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct Addr {
  /// Timestamped v1 address entries.
  pub addrs: Vec<TimestampedAddr>,
}

impl Codec for Addr {
  fn decode(data: &mut &[u8]) -> Result<Self, DecodeError> {
    Ok(Self { addrs: codec::read_vec(data, MAX_ADDR)? })
  }

  fn encode(&self, buf: &mut Vec<u8>) {
    codec::write_vec(&self.addrs, buf);
  }
}

crate::codec::impl_p2p!(Addr);

/// BIP155 v2 address announcement.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct AddrV2Msg {
  /// BIP155 address entries.
  pub addrs: Vec<AddrV2Entry>,
}

impl Codec for AddrV2Msg {
  fn decode(data: &mut &[u8]) -> Result<Self, DecodeError> {
    Ok(Self { addrs: codec::read_vec(data, MAX_ADDR)? })
  }

  fn encode(&self, buf: &mut Vec<u8>) {
    codec::write_vec(&self.addrs, buf);
  }
}

crate::codec::impl_p2p!(AddrV2Msg);
