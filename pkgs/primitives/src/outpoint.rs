//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Transaction outpoint (36 bytes).

use crate::prelude::*;
use crate::TxHash;

use dash_types::codec::{self, Codec, DecodeError};

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
    let hash = TxHash::decode(data)?;
    let index = codec::read_u32_le(data)?;
    Ok(Self { hash, index })
  }

  fn encode(&self, buf: &mut Vec<u8>) {
    buf.extend_from_slice(self.hash.as_bytes());
    buf.extend_from_slice(&self.index.to_le_bytes());
  }
}

dash_types::impl_type!(OutPoint);

impl fmt::Display for OutPoint {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "{}:{}", self.hash, self.index)
  }
}
