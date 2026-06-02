//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Compact difficulty target encoding.

use crate::Arith256;

use core::fmt;

/// Compact difficulty target — a newtype around the consensus `nBits` u32.
///
/// Construct directly via `CompactTarget(0x1d00ffff)`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CompactTarget(pub u32);

/// Result of decoding a compact difficulty target.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub struct DecodedTarget {
  /// The decoded 256-bit target value.
  pub value: Arith256,
  /// Whether the sign bit was set in the mantissa.
  pub negative: bool,
  /// Whether the encoded exponent exceeds the valid range.
  pub overflow: bool,
}

impl CompactTarget {
  /// Decode this compact (nBits) representation into a 256-bit target value.
  pub const fn decode(self) -> DecodedTarget {
    let compact = self.0;
    let size = (compact >> 24) as usize;
    let mut word = compact & 0x007f_ffff;

    let value = if size <= 3 {
      word >>= 8 * (3 - size);
      Arith256::from_u64(word as u64)
    } else {
      let v = Arith256::from_u64(word as u64);
      v.wrapping_shl((8 * (size - 3)) as u32)
    };

    let negative = word != 0 && (compact & 0x0080_0000) != 0;
    let overflow = word != 0 && ((size > 34) || (word > 0xff && size > 33) || (word > 0xffff && size > 32));

    DecodedTarget {
      value,
      negative,
      overflow,
    }
  }
}

impl fmt::Display for CompactTarget {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "{:#010x}", self.0)
  }
}

impl Arith256 {
  /// Decode a compact (nBits) representation into a 256-bit target value.
  ///
  /// Convenience method that delegates to [`CompactTarget::decode`].
  pub const fn from_compact(ct: CompactTarget) -> DecodedTarget {
    ct.decode()
  }

  /// Encode this value as a compact (nBits) representation.
  pub const fn to_compact(self, negative: bool) -> CompactTarget {
    let mut size = self.bits().div_ceil(8);
    let mut compact: u32 = if size <= 3 {
      (self.low_u64() << (8 * (3 - size as u64))) as u32
    } else {
      let bn = self.wrapping_shr(8 * (size - 3));
      bn.low_u64() as u32
    };

    // Bit 23 denotes the sign. When already set, shift the mantissa right
    // and bump the exponent.
    if compact & 0x0080_0000 != 0 {
      compact >>= 8;
      size += 1;
    }

    compact &= 0x007f_ffff;
    compact |= size << 24;
    if negative && (compact & 0x007f_ffff) != 0 {
      compact |= 0x0080_0000;
    }

    CompactTarget(compact)
  }
}

impl bitcoin_consensus_encoding::Encodable for CompactTarget {
  type Encoder<'e> = bitcoin_consensus_encoding::ArrayEncoder<4>;

  fn encoder(&self) -> Self::Encoder<'_> {
    bitcoin_consensus_encoding::ArrayEncoder::without_length_prefix(self.0.to_le_bytes())
  }
}

impl bitcoin_consensus_encoding::Decodable for CompactTarget {
  type Decoder = CompactTargetDecoder;

  fn decoder() -> Self::Decoder {
    CompactTargetDecoder(bitcoin_consensus_encoding::ArrayDecoder::new())
  }
}

/// Decoder for [`CompactTarget`].
#[derive(Clone, Debug)]
pub struct CompactTargetDecoder(bitcoin_consensus_encoding::ArrayDecoder<4>);

impl bitcoin_consensus_encoding::Decoder for CompactTargetDecoder {
  type Output = CompactTarget;
  type Error = crate::HashDecoderError;

  #[inline]
  fn push_bytes(&mut self, bytes: &mut &[u8]) -> Result<bool, Self::Error> {
    self.0.push_bytes(bytes).map_err(crate::HashDecoderError)
  }

  #[inline]
  fn end(self) -> Result<Self::Output, Self::Error> {
    let bytes = self.0.end().map_err(crate::HashDecoderError)?;
    Ok(CompactTarget(u32::from_le_bytes(bytes)))
  }

  #[inline]
  fn read_limit(&self) -> usize {
    self.0.read_limit()
  }
}

#[cfg(feature = "serde")]
impl serde::Serialize for CompactTarget {
  fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
    self.0.serialize(serializer)
  }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for CompactTarget {
  fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
    u32::deserialize(deserializer).map(CompactTarget)
  }
}
