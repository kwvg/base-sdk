//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Twelve-byte null-padded command string for P2P message dispatch.

use dash_primitives::hash_impl;
use dash_types::type_id::TypeId;
use dash_types::{impl_bytes, type_cvrt};

use core::fmt;

/// A 12-byte, null-padded ASCII command identifying a P2P message type.
#[derive(Clone, Copy, Eq, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct CommandString([u8; 12]);

impl_bytes!(CommandString, 12);

hash_impl!(CommandString);

impl CommandString {
  /// Builds a command string from a static `&str` at compile time.
  ///
  /// # Panics
  ///
  /// Compile-time panic if `s` is longer than 12 bytes.
  pub const fn from_static(s: &str) -> Self {
    let b = s.as_bytes();
    let len = b.len();
    assert!(len <= 12, "command string exceeds 12 bytes");
    let mut buf = [0u8; 12];
    let mut i = 0;
    while i < len {
      buf[i] = b[i];
      i += 1;
    }
    Self(buf)
  }

  /// Wraps raw bytes into a command string.
  pub const fn from_bytes(bytes: [u8; 12]) -> Self {
    Self(bytes)
  }

  /// Returns the raw 12-byte command buffer.
  pub const fn as_bytes(&self) -> &[u8; 12] {
    &self.0
  }

  /// Returns the bytes before the first null, or an empty string when those
  /// bytes are not UTF-8.
  pub fn as_str(&self) -> &str {
    let end = self.0.iter().position(|&b| b == 0).unwrap_or(12);
    core::str::from_utf8(&self.0[..end]).unwrap_or("")
  }
}

type_cvrt!(From<[u8; 12]> for CommandString, |bytes| Self(*bytes));

impl fmt::Debug for CommandString {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "CommandString(\"{}\")", self.as_str())
  }
}

impl fmt::Display for CommandString {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.write_str(self.as_str())
  }
}

#[cfg(test)]
mod tests {
  use super::CommandString;

  use rstest::rstest;

  #[rstest]
  #[case::padded(*b"ping\0\0\0\0\0\0\0\0", "ping")]
  #[case::full(*b"sendheaders2", "sendheaders2")]
  #[case::not_utf8([0xff, b'a', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], "")]
  fn as_str_stops_at_the_first_null(#[case] bytes: [u8; 12], #[case] expected: &str) {
    assert_eq!(CommandString::from_bytes(bytes).as_str(), expected);
  }
}
