//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Public key hash identifier (HASH160).

use crate::prelude::*;

use core::fmt;

/// 20-byte public key hash (RIPEMD-160 of SHA-256).
#[derive(Clone, Copy, Default, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(transparent))]
pub struct KeyId(#[cfg_attr(feature = "serde", serde(with = "dash_types::serialize::hex::w20"))] pub [u8; 20]);

impl KeyId {
  /// Returns the inner byte array.
  pub const fn to_bytes(self) -> [u8; 20] {
    self.0
  }

  /// Borrows the inner byte array.
  pub const fn as_bytes(&self) -> &[u8; 20] {
    &self.0
  }

  /// Returns `true` when every byte is zero.
  pub fn is_null(&self) -> bool {
    self.0.iter().all(|&b| b == 0)
  }
}

impl From<[u8; 20]> for KeyId {
  fn from(bytes: [u8; 20]) -> Self {
    Self(bytes)
  }
}

impl From<KeyId> for [u8; 20] {
  fn from(val: KeyId) -> Self {
    val.0
  }
}

impl AsRef<[u8]> for KeyId {
  fn as_ref(&self) -> &[u8] {
    &self.0
  }
}

impl AsRef<[u8; 20]> for KeyId {
  fn as_ref(&self) -> &[u8; 20] {
    &self.0
  }
}

impl fmt::Debug for KeyId {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "KeyId(")?;
    for byte in &self.0 {
      write!(f, "{:02x}", byte)?;
    }
    write!(f, ")")
  }
}

impl fmt::Display for KeyId {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    for byte in &self.0 {
      write!(f, "{:02x}", byte)?;
    }
    Ok(())
  }
}

// Consensus encoding.

impl dash_types::codec::Codec for KeyId {
  fn decode(data: &mut &[u8]) -> Result<Self, dash_types::codec::DecodeError> {
    dash_types::codec::take::<20>(data).map(Self)
  }

  fn encode(&self, buf: &mut Vec<u8>) {
    buf.extend_from_slice(&self.0);
  }
}

dash_types::impl_type!(KeyId);
