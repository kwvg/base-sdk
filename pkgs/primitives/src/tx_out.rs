//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Transaction output.

use crate::prelude::*;
use crate::script::Script;

use bitcoin_units::Amount;
use dash_types::codec::{self, Codec, DecodeError};

use core::fmt;

/// A transaction output.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct TxOut {
  /// Output value in duffs.
  #[cfg_attr(feature = "serde", serde(with = "crate::serialize::amount"))]
  pub value: Amount,
  /// Locking script.
  pub script_pubkey: Script,
}

impl Codec for TxOut {
  fn decode(data: &mut &[u8]) -> Result<Self, DecodeError> {
    let raw = codec::read_u64_le(data)?;
    let value = Amount::from_sat(raw).map_err(|_| DecodeError::Custom {
      msg: "txout value exceeds MAX_MONEY",
    })?;
    let script_pubkey = Script::decode(data)?;
    Ok(Self { value, script_pubkey })
  }

  fn encode(&self, buf: &mut Vec<u8>) {
    buf.extend_from_slice(&self.value.to_sat().to_le_bytes());
    self.script_pubkey.encode(buf);
  }
}

dash_types::impl_type!(TxOut);

impl fmt::Display for TxOut {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "TxOut {{ value: {} }}", self.value.to_sat())
  }
}
