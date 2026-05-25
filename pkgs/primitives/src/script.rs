//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Variable-length script with CompactSize-prefixed consensus encoding.

use crate::prelude::*;

use dash_types::codec::{self, Codec, DecodeError};

use core::fmt;

/// Maximum serialized object size (32 MiB).
const MAX_SIZE: usize = 0x0200_0000;

/// A variable-length script, CompactSize-prefixed on the wire.
#[derive(Clone, PartialEq, Eq, Hash, Default)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(transparent))]
pub struct Script(#[cfg_attr(feature = "serde", serde(with = "dash_types::serialize::hex"))] pub Vec<u8>);

impl Script {
  /// Creates a new script from raw bytes.
  pub fn new(data: Vec<u8>) -> Self {
    Self(data)
  }

  /// Returns a reference to the script bytes.
  pub fn as_bytes(&self) -> &[u8] {
    &self.0
  }

  /// Returns the length in bytes.
  pub fn len(&self) -> usize {
    self.0.len()
  }

  /// Returns whether the script is empty.
  pub fn is_empty(&self) -> bool {
    self.0.is_empty()
  }
}

impl fmt::Debug for Script {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "Script(")?;
    for byte in &self.0 {
      write!(f, "{:02x}", byte)?;
    }
    write!(f, ")")
  }
}

impl fmt::Display for Script {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    for byte in &self.0 {
      write!(f, "{:02x}", byte)?;
    }
    Ok(())
  }
}

impl Codec for Script {
  fn decode(data: &mut &[u8]) -> Result<Self, DecodeError> {
    codec::read_vec(data, MAX_SIZE).map(Self)
  }

  fn encode(&self, buf: &mut Vec<u8>) {
    codec::write_compact_size(self.0.len(), buf);
    buf.extend_from_slice(&self.0);
  }
}

dash_types::impl_type!(Script);
