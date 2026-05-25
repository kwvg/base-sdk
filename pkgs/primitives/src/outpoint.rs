//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Transaction outpoint (36 bytes).

use crate::prelude::*;
use crate::TxHash;

use dash_types::codec::{Codec, DecodeError};

use core::fmt;

/// A reference to a previous transaction output.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct OutPoint {
  /// Transaction hash of the referenced output.
  pub hash: TxHash,
  /// Index of the referenced output within the transaction.
  pub index: u32,
}

impl Codec for OutPoint {
  fn decode(data: &mut &[u8]) -> Result<Self, DecodeError> {
    Ok(Self {
      hash: TxHash::decode(data)?,
      index: u32::decode(data)?,
    })
  }

  fn encode(&self, buf: &mut Vec<u8>) {
    self.hash.encode(buf);
    self.index.encode(buf);
  }
}

dash_types::impl_type!(OutPoint);

impl fmt::Display for OutPoint {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "{}:{}", self.hash, self.index)
  }
}
