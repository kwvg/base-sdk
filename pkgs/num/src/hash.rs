//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Fixed-size opaque hash blob types.

use crate::ParseHexError;

use core::fmt;
use core::hash::Hash;
use core::str::FromStr;

pub(crate) const HEX_LOWER: [u8; 16] = *b"0123456789abcdef";

pub(crate) fn hex_val(c: u8) -> Result<u8, ParseHexError> {
  match c {
    b'0'..=b'9' => Ok(c - b'0'),
    b'a'..=b'f' => Ok(c - b'a' + 10),
    b'A'..=b'F' => Ok(c - b'A' + 10),
    _ => Err(ParseHexError::InvalidChar(c)),
  }
}

/// Shared interface for all fixed-size hash blob types.
pub trait HashBlob:
  Copy + Clone + Default + Eq + Ord + Hash + fmt::Debug + fmt::Display + fmt::LowerHex + FromStr + AsRef<[u8]>
{
  /// The fixed-size byte array type.
  type Bytes: Copy;

  /// The all-zeros (null) hash.
  const ZERO: Self;
  /// Byte length of this hash type.
  const LEN: usize;

  /// Wrap raw little-endian bytes into a hash.
  fn from_bytes(bytes: Self::Bytes) -> Self;
  /// Return the raw little-endian bytes.
  fn to_bytes(self) -> Self::Bytes;
  /// Borrow the raw little-endian bytes.
  fn as_bytes(&self) -> &Self::Bytes;
  /// Construct from big-endian bytes (consensus display order).
  fn new(be: Self::Bytes) -> Self;
  /// Returns `true` if every byte is zero.
  fn is_null(&self) -> bool;
  /// Parse from a big-endian hex string.
  fn from_hex(s: &str) -> Result<Self, ParseHexError>;
}

macro_rules! define_hash {
  ($name:ident, $n:literal, $serde_with:literal) => {
    /// Fixed-size opaque hash blob stored in little-endian byte order.
    #[derive(Clone, Copy, Eq, Hash, PartialEq)]
    #[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
    #[cfg_attr(feature = "serde", serde(transparent))]
    pub struct $name(#[cfg_attr(feature = "serde", serde(with = $serde_with))] [u8; $n]);

    impl $name {
      /// The all-zeros (null) hash.
      pub const ZERO: Self = Self([0u8; $n]);
      /// Byte length of this hash type.
      pub const LEN: usize = $n;

      /// Wrap raw little-endian bytes into a hash.
      #[inline]
      pub const fn from_bytes(bytes: [u8; $n]) -> Self {
        Self(bytes)
      }

      /// Return the raw little-endian bytes.
      #[inline]
      pub const fn to_bytes(self) -> [u8; $n] {
        self.0
      }

      /// Borrow the raw little-endian bytes.
      #[inline]
      pub const fn as_bytes(&self) -> &[u8; $n] {
        &self.0
      }

      /// Construct from big-endian bytes (consensus display order).
      ///
      /// This is the natural byte order produced by `hex_literal::hex!()` when
      /// given a block hash or other consensus hex value. Internally the bytes
      /// are stored little-endian, so this reverses the input.
      #[inline]
      pub const fn new(be: [u8; $n]) -> Self {
        let mut le = [0u8; $n];
        let mut i = 0;
        while i < $n {
          le[i] = be[$n - 1 - i];
          i += 1;
        }
        Self(le)
      }

      /// Returns `true` if every byte is zero.
      pub const fn is_null(&self) -> bool {
        let mut i = 0;
        while i < $n {
          if self.0[i] != 0 {
            return false;
          }
          i += 1;
        }
        true
      }

      /// Parse from a big-endian hex string.
      ///
      /// Accepts an optional `0x`/`0X` prefix followed by optional leading
      /// spaces before the hex digits. The digits are big-endian (most
      /// significant byte first), mirroring the consensus display convention.
      ///
      /// # Errors
      ///
      /// Returns `OddLength` when the input has an odd
      /// number of hex characters, `InvalidLength` when the
      /// decoded byte count exceeds the type width, or
      /// `InvalidChar` on a non-hex digit.
      pub fn from_hex(s: &str) -> Result<Self, ParseHexError> {
        let s = s.as_bytes();

        // strip optional 0x prefix
        let s = if s.len() >= 2 && s[0] == b'0' && (s[1] == b'x' || s[1] == b'X') {
          &s[2..]
        } else {
          s
        };

        // skip leading whitespace
        let mut start = 0;
        while start < s.len() && s[start] == b' ' {
          start += 1;
        }
        let s = &s[start..];

        if s.len() % 2 != 0 {
          return Err(ParseHexError::OddLength);
        }

        let byte_len = s.len() / 2;
        if byte_len > $n {
          return Err(ParseHexError::InvalidLength {
            expected: $n * 2,
            got: s.len(),
          });
        }

        let mut bytes = [0u8; $n];
        // Big-endian hex: first byte is most significant,
        // stored last in the little-endian array.
        let mut i = 0;
        while i < byte_len {
          let hi = hex_val(s[i * 2])?;
          let lo = hex_val(s[i * 2 + 1])?;
          bytes[byte_len - 1 - i] = (hi << 4) | lo;
          i += 1;
        }

        Ok(Self(bytes))
      }
    }

    impl HashBlob for $name {
      type Bytes = [u8; $n];
      const ZERO: Self = Self::ZERO;
      const LEN: usize = $n;

      #[inline]
      fn from_bytes(bytes: [u8; $n]) -> Self {
        Self::from_bytes(bytes)
      }

      #[inline]
      fn to_bytes(self) -> [u8; $n] {
        Self::to_bytes(self)
      }

      #[inline]
      fn as_bytes(&self) -> &[u8; $n] {
        Self::as_bytes(self)
      }

      #[inline]
      fn new(be: [u8; $n]) -> Self {
        Self::new(be)
      }

      #[inline]
      fn is_null(&self) -> bool {
        Self::is_null(self)
      }

      #[inline]
      fn from_hex(s: &str) -> Result<Self, ParseHexError> {
        Self::from_hex(s)
      }
    }

    impl Default for $name {
      fn default() -> Self {
        Self::ZERO
      }
    }

    impl Ord for $name {
      fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        // Lexicographic on raw bytes (consensus ordering).
        self.0.cmp(&other.0)
      }
    }

    impl PartialOrd for $name {
      fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
      }
    }

    /// Reversed hex (big-endian display, consensus format).
    impl fmt::Display for $name {
      fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for i in (0..$n).rev() {
          let b = self.0[i];
          let c1 = HEX_LOWER[(b >> 4) as usize] as char;
          let c2 = HEX_LOWER[(b & 0x0f) as usize] as char;
          f.write_fmt(format_args!("{c1}{c2}"))?;
        }
        Ok(())
      }
    }

    impl fmt::LowerHex for $name {
      fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
      }
    }

    impl fmt::Debug for $name {
      fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}({})", stringify!($name), self)
      }
    }

    impl FromStr for $name {
      type Err = ParseHexError;

      fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_hex(s)
      }
    }

    impl From<[u8; $n]> for $name {
      fn from(bytes: [u8; $n]) -> Self {
        Self(bytes)
      }
    }

    impl From<$name> for [u8; $n] {
      fn from(h: $name) -> Self {
        h.0
      }
    }

    impl AsRef<[u8]> for $name {
      fn as_ref(&self) -> &[u8] {
        &self.0
      }
    }

    impl AsRef<[u8; $n]> for $name {
      fn as_ref(&self) -> &[u8; $n] {
        &self.0
      }
    }

    impl bitcoin_consensus_encoding::Encodable for $name {
      type Encoder<'e> = bitcoin_consensus_encoding::ArrayRefEncoder<'e, $n>;

      fn encoder(&self) -> Self::Encoder<'_> {
        bitcoin_consensus_encoding::ArrayRefEncoder::without_length_prefix(&self.0)
      }
    }

    impl bitcoin_consensus_encoding::Decodable for $name {
      type Decoder = $crate::HashTypeDecoder<$name, $n>;
      fn decoder() -> Self::Decoder {
        $crate::HashTypeDecoder::new()
      }
    }
  };
}

define_hash!(Hash160, 20, "crate::serialize::hex_blob::w20");
define_hash!(Hash256, 32, "crate::serialize::hex_blob::w32");
define_hash!(Hash512, 64, "crate::serialize::hex_blob::w64");

impl Hash512 {
  /// Truncate to 256 bits by taking the first 32 bytes (low half in LE).
  ///
  /// This is the final step in the proof-of-work daisy chain: the 512-bit
  /// intermediate result is truncated to 256 bits.
  pub const fn truncate(&self) -> Hash256 {
    let mut out = [0u8; 32];
    let mut i = 0;
    while i < 32 {
      out[i] = self.0[i];
      i += 1;
    }
    Hash256::from_bytes(out)
  }
}
