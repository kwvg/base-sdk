//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! P2P-layer decoding and check errors.

use crate::prelude::*;

use dash_types::codec::DecodeError;
use dash_types::type_id::Unencodable;

use core::fmt;

/// An error encountered during P2P message decoding.
#[derive(Clone, Debug, Eq, Hash, PartialEq, Unencodable)]
pub enum P2pDecodeError {
  /// Underlying consensus decoding error.
  Consensus(String),
  /// Unrecognised 12-byte command string.
  UnknownCommand {
    /// The raw command bytes.
    bytes: [u8; 12],
  },
  /// V2 short ID does not map to a known message.
  UnknownShortId {
    /// The short ID byte.
    id: u8,
  },
  /// Message payload exceeds the allowed size.
  PayloadTooLarge {
    /// Wire command name.
    command: &'static str,
    /// Size of the raw payload, in bytes.
    size: usize,
    /// Maximum allowed size, in bytes.
    max: usize,
  },
  /// Message carries a payload where none is permitted.
  PayloadNotEmpty {
    /// Wire command name.
    command: &'static str,
    /// Size of the raw payload, in bytes.
    size: usize,
  },
  /// A field value is outside the valid range.
  InvalidValue {
    /// Brief description of what was invalid.
    field: &'static str,
  },
}

impl From<DecodeError> for P2pDecodeError {
  fn from(e: DecodeError) -> Self {
    Self::Consensus(format!("{e}"))
  }
}

impl fmt::Display for P2pDecodeError {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    match self {
      Self::Consensus(e) => write!(f, "{e}"),
      Self::UnknownCommand { bytes } => {
        write!(f, "unknown command: ")?;
        for &b in bytes {
          if b == 0 {
            break;
          }
          if b.is_ascii_graphic() || b == b' ' {
            write!(f, "{}", b as char)?;
          } else {
            write!(f, "\\x{b:02x}")?;
          }
        }
        Ok(())
      }
      Self::UnknownShortId { id } => {
        write!(f, "unknown v2 short id: {id}")
      }
      Self::PayloadTooLarge { command, size, max } => {
        write!(f, "{command} payload too large: {size} bytes, max {max}")
      }
      Self::PayloadNotEmpty { command, size } => {
        write!(f, "{command} must have an empty payload, got {size} bytes")
      }
      Self::InvalidValue { field } => {
        write!(f, "invalid value for {field}")
      }
    }
  }
}

#[cfg(feature = "std")]
impl std::error::Error for P2pDecodeError {}

/// A message carries more entries than its limit allows.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Unencodable)]
pub struct TooManyEntries {
  /// Number of entries carried.
  pub count: usize,
  /// Largest number of entries allowed.
  pub limit: usize,
}

impl fmt::Display for TooManyEntries {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "{} entries exceed the limit of {}", self.count, self.limit)
  }
}

/// Returns an error when `count` exceeds `limit`.
pub(crate) fn check_count(count: usize, limit: usize) -> Option<TooManyEntries> {
  (count > limit).then_some(TooManyEntries { count, limit })
}
