//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Ping and Pong keepalive messages.

use crate::prelude::*;

use dash_types::codec::{self, Codec, DecodeError};

/// Keepalive request carrying a random nonce.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct Ping {
  /// Random nonce echoed back in the corresponding `Pong`.
  pub nonce: u64,
}

impl Codec for Ping {
  fn decode(data: &mut &[u8]) -> Result<Self, DecodeError> {
    Ok(Self {
      nonce: codec::read_u64_le(data)?,
    })
  }

  fn encode(&self, buf: &mut Vec<u8>) {
    buf.extend_from_slice(&self.nonce.to_le_bytes());
  }
}

crate::codec::impl_p2p!(Ping);

/// Keepalive response echoing the nonce from a `Ping`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct Pong {
  /// Nonce from the original `Ping`.
  pub nonce: u64,
}

impl Codec for Pong {
  fn decode(data: &mut &[u8]) -> Result<Self, DecodeError> {
    Ok(Self {
      nonce: codec::read_u64_le(data)?,
    })
  }

  fn encode(&self, buf: &mut Vec<u8>) {
    buf.extend_from_slice(&self.nonce.to_le_bytes());
  }
}

crate::codec::impl_p2p!(Pong);
