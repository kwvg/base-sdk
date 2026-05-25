//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! P2P-layer decoding errors.

use crate::prelude::*;

use core::fmt;

/// An error encountered during P2P message decoding.
#[derive(Debug, Clone, PartialEq, Eq)]
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
    /// Actual decoded size.
    size: usize,
    /// Maximum allowed size.
    max: usize,
  },
  /// A field value is outside the valid range.
  InvalidValue {
    /// Brief description of what was invalid.
    field: &'static str,
  },
}

impl From<dash_primitives::codec::DecodeError> for P2pDecodeError {
  fn from(e: dash_primitives::codec::DecodeError) -> Self {
    Self::Consensus(format!("{e}"))
  }
}

impl From<crate::encode::WireDecodeError> for P2pDecodeError {
  fn from(e: crate::encode::WireDecodeError) -> Self {
    Self::Consensus(e.0)
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
      Self::InvalidValue { field } => {
        write!(f, "invalid value for {field}")
      }
    }
  }
}

#[cfg(feature = "std")]
impl std::error::Error for P2pDecodeError {}
