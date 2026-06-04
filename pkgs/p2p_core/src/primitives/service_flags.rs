//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Dash service flag bitfield.

use bitcoin_consensus_encoding as encoding;

use core::fmt;
use core::ops;

/// Bitfield advertised in `version` messages describing node capabilities.
#[derive(Clone, Copy, Default, Eq, Hash, PartialEq)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct ServiceFlags(pub u64);

impl ServiceFlags {
  /// No services.
  pub const NONE: Self = Self(0);
  /// Full blockchain data.
  pub const NODE_NETWORK: Self = Self(1 << 0);
  /// BIP37 bloom filters.
  pub const NODE_BLOOM: Self = Self(1 << 2);
  /// BIP157 compact block filters.
  pub const NODE_COMPACT_FILTERS: Self = Self(1 << 6);
  /// Last 288 blocks only.
  pub const NODE_NETWORK_LIMITED: Self = Self(1 << 10);
  /// Dash compressed headers (headers2).
  pub const NODE_HEADERS_COMPRESSED: Self = Self(1 << 11);
  /// BIP324 v2 transport.
  pub const NODE_P2P_V2: Self = Self(1 << 12);

  /// Returns `true` if all bits in `flag` are set.
  pub const fn has(self, flag: Self) -> bool {
    self.0 & flag.0 == flag.0
  }

  /// Returns the raw `u64` value.
  pub const fn to_u64(self) -> u64 {
    self.0
  }
}

impl ops::BitOr for ServiceFlags {
  type Output = Self;
  fn bitor(self, rhs: Self) -> Self {
    Self(self.0 | rhs.0)
  }
}

impl ops::BitAnd for ServiceFlags {
  type Output = Self;
  fn bitand(self, rhs: Self) -> Self {
    Self(self.0 & rhs.0)
  }
}

impl ops::BitOrAssign for ServiceFlags {
  fn bitor_assign(&mut self, rhs: Self) {
    self.0 |= rhs.0;
  }
}

impl fmt::Debug for ServiceFlags {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "ServiceFlags(0x{:016x})", self.0)
  }
}

impl fmt::Display for ServiceFlags {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "0x{:x}", self.0)
  }
}

encoding::encoder_newtype_exact! {
  /// Encoder for [`ServiceFlags`].
  pub struct ServiceFlagsEncoder<'e>(encoding::ArrayEncoder<8>);
}

impl encoding::Encodable for ServiceFlags {
  type Encoder<'e> = ServiceFlagsEncoder<'e>;
  fn encoder(&self) -> Self::Encoder<'_> {
    ServiceFlagsEncoder::new(encoding::ArrayEncoder::without_length_prefix(self.0.to_le_bytes()))
  }
}

/// Decoder for [`ServiceFlags`].
#[derive(Clone, Debug)]
pub struct ServiceFlagsDecoder(encoding::ArrayDecoder<8>);

impl ServiceFlagsDecoder {
  /// Creates a new decoder.
  pub const fn new() -> Self {
    Self(encoding::ArrayDecoder::new())
  }
}

impl Default for ServiceFlagsDecoder {
  fn default() -> Self {
    Self::new()
  }
}

/// Decode error for [`ServiceFlags`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceFlagsDecoderError(encoding::UnexpectedEofError);

impl fmt::Display for ServiceFlagsDecoderError {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "service flags decode: {}", self.0)
  }
}

impl encoding::Decoder for ServiceFlagsDecoder {
  type Output = ServiceFlags;
  type Error = ServiceFlagsDecoderError;

  fn push_bytes(&mut self, bytes: &mut &[u8]) -> Result<bool, Self::Error> {
    self.0.push_bytes(bytes).map_err(ServiceFlagsDecoderError)
  }

  fn end(self) -> Result<Self::Output, Self::Error> {
    let buf = self.0.end().map_err(ServiceFlagsDecoderError)?;
    Ok(ServiceFlags(u64::from_le_bytes(buf)))
  }

  fn read_limit(&self) -> usize {
    self.0.read_limit()
  }
}

impl encoding::Decodable for ServiceFlags {
  type Decoder = ServiceFlagsDecoder;
  fn decoder() -> Self::Decoder {
    ServiceFlagsDecoder::new()
  }
}
