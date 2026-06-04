//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Reusable serde helpers for `#[serde(with = "...")]`.

use crate::support::LlmqType;
use crate::tx_types::{MnType, TxType};

use dash_types::{AsUint, TryFromUint};

pub use dash_types::serialize::uint;

/// Serializes [`Amount`](bitcoin_units::Amount) as a `u64` (satoshis).
pub mod amount {
  use bitcoin_units::Amount;

  /// Serializes as raw satoshis.
  pub fn serialize<S: serde::Serializer>(val: &Amount, serializer: S) -> Result<S::Ok, S::Error> {
    serializer.serialize_u64(val.to_sat())
  }

  /// Deserializes from raw satoshis.
  pub fn deserialize<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<Amount, D::Error> {
    let sat = <u64 as serde::Deserialize>::deserialize(deserializer)?;
    Amount::from_sat(sat).map_err(serde::de::Error::custom)
  }
}

impl AsUint<u8> for LlmqType {
  fn as_uint(&self) -> u8 {
    self.to_u8()
  }
}

impl TryFromUint<u8> for LlmqType {
  type Err = core::convert::Infallible;

  fn try_from_uint(v: u8) -> Result<Self, Self::Err> {
    Ok(Self::from_u8(v))
  }
}

impl AsUint<u16> for TxType {
  fn as_uint(&self) -> u16 {
    self.to_u16()
  }
}

impl TryFromUint<u16> for TxType {
  type Err = core::convert::Infallible;

  fn try_from_uint(v: u16) -> Result<Self, Self::Err> {
    Ok(Self::from_u16(v))
  }
}

impl AsUint<u16> for MnType {
  fn as_uint(&self) -> u16 {
    self.to_u16()
  }
}

impl TryFromUint<u16> for MnType {
  type Err = core::convert::Infallible;

  fn try_from_uint(v: u16) -> Result<Self, Self::Err> {
    Ok(Self::from_u16(v))
  }
}
