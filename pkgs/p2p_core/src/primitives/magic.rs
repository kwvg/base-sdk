//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Dash network magic bytes.

use core::fmt;

/// Four-byte network identifier prepended to every V1 message.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct Magic(pub [u8; 4]);

impl Magic {
  /// Returns the inner byte array.
  pub const fn to_bytes(self) -> [u8; 4] {
    self.0
  }

  /// Borrows the inner byte array.
  pub const fn as_bytes(&self) -> &[u8; 4] {
    &self.0
  }
}

impl From<Magic> for [u8; 4] {
  fn from(val: Magic) -> Self {
    val.0
  }
}

impl AsRef<[u8]> for Magic {
  fn as_ref(&self) -> &[u8] {
    &self.0
  }
}

impl fmt::Debug for Magic {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "Magic(")?;
    for byte in &self.0 {
      write!(f, "{:02x}", byte)?;
    }
    write!(f, ")")
  }
}

impl fmt::Display for Magic {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    for byte in &self.0 {
      write!(f, "{:02x}", byte)?;
    }
    Ok(())
  }
}

dash_types::impl_bytes!(4, Magic);
