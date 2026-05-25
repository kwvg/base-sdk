//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Transaction input.

use crate::outpoint::OutPoint;
use crate::prelude::*;
use crate::script::Script;

use dash_types::codec::{Codec, DecodeError};

use core::fmt;

/// A transaction input.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct TxIn {
  /// The outpoint being spent.
  pub prevout: OutPoint,
  /// Unlocking script.
  pub script_sig: Script,
  /// Sequence number.
  pub sequence: u32,
}

impl Codec for TxIn {
  fn decode(data: &mut &[u8]) -> Result<Self, DecodeError> {
    Ok(Self {
      prevout: OutPoint::decode(data)?,
      script_sig: Script::decode(data)?,
      sequence: u32::decode(data)?,
    })
  }

  fn encode(&self, buf: &mut Vec<u8>) {
    self.prevout.encode(buf);
    self.script_sig.encode(buf);
    self.sequence.encode(buf);
  }
}

dash_types::impl_type!(TxIn);

impl fmt::Display for TxIn {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "TxIn {{ prevout: {}, seq: {} }}", self.prevout, self.sequence,)
  }
}
