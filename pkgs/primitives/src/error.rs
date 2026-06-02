//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Consensus decoding errors.

use core::fmt;

/// An error encountered during consensus decoding.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum DecodeError {
  /// Not enough bytes remaining in the cursor.
  Eof {
    /// Bytes needed for the read.
    needed: usize,
    /// Bytes actually remaining.
    remaining: usize,
  },
  /// CompactSize encoding is not minimal.
  NonMinimalCompactSize {
    /// The decoded value that was not minimally encoded.
    value: u64,
  },
  /// CompactSize value exceeds the allowed limit.
  CompactSizeExceedsLimit {
    /// The configured limit.
    limit: usize,
    /// The decoded value.
    value: u64,
  },
}

impl fmt::Display for DecodeError {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    match self {
      Self::Eof { needed, remaining } => write!(f, "unexpected eof: needed {needed} bytes, {remaining} remaining",),
      Self::NonMinimalCompactSize { value } => write!(f, "non-minimal compact size encoding for value {value}",),
      Self::CompactSizeExceedsLimit { limit, value } => write!(f, "compact size value {value} exceeds limit {limit}",),
    }
  }
}

#[cfg(feature = "std")]
impl std::error::Error for DecodeError {}
