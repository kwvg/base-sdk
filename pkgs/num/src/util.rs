//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Hash256 newtype macro and decoder.

/// Generates a newtype wrapping `dash_num::Hash256` with full trait
/// implementations and consensus encoding support.
#[macro_export]
macro_rules! make_hash256 {
  (
    $(#[$attr:meta])*
    $name:ident
  ) => {
    $(#[$attr])*
    #[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
    #[cfg_attr(feature = "serde", serde(transparent))]
    pub struct $name($crate::Hash256);

    impl $name {
      /// The all-zeros (null) hash.
      pub const ZERO: Self = Self($crate::Hash256::ZERO);

      /// Wrap raw little-endian bytes into a hash.
      #[inline]
      pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self($crate::Hash256::from_bytes(bytes))
      }

      /// Return the raw little-endian bytes.
      #[inline]
      pub const fn to_bytes(self) -> [u8; 32] {
        self.0.to_bytes()
      }

      /// Borrow the raw little-endian bytes.
      #[inline]
      pub const fn as_bytes(&self) -> &[u8; 32] {
        self.0.as_bytes()
      }

      /// Construct from big-endian bytes (consensus display order).
      #[inline]
      pub const fn new(be: [u8; 32]) -> Self {
        Self($crate::Hash256::new(be))
      }

      /// Returns `true` if every byte is zero.
      #[inline]
      pub const fn is_null(&self) -> bool {
        self.0.is_null()
      }

      /// Parse from a big-endian hex string.
      #[inline]
      pub fn from_hex(s: &str) -> Result<Self, $crate::ParseHexError> {
        $crate::Hash256::from_hex(s).map(Self)
      }
    }

    impl Default for $name {
      #[inline]
      fn default() -> Self { Self::ZERO }
    }

    impl core::fmt::Display for $name {
      fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        core::fmt::Display::fmt(&self.0, f)
      }
    }

    impl core::fmt::Debug for $name {
      fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}({})", stringify!($name), self.0)
      }
    }

    impl core::str::FromStr for $name {
      type Err = $crate::ParseHexError;

      fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_hex(s)
      }
    }

    impl From<[u8; 32]> for $name {
      #[inline]
      fn from(bytes: [u8; 32]) -> Self { Self::from_bytes(bytes) }
    }

    impl From<$name> for [u8; 32] {
      #[inline]
      fn from(h: $name) -> Self { h.to_bytes() }
    }

    impl From<$crate::Hash256> for $name {
      #[inline]
      fn from(h: $crate::Hash256) -> Self { Self(h) }
    }

    impl From<$name> for $crate::Hash256 {
      #[inline]
      fn from(h: $name) -> Self { h.0 }
    }

    impl AsRef<[u8]> for $name {
      #[inline]
      fn as_ref(&self) -> &[u8] { self.0.as_ref() }
    }

    impl AsRef<[u8; 32]> for $name {
      #[inline]
      fn as_ref(&self) -> &[u8; 32] { self.0.as_bytes() }
    }

    impl $crate::__private::bitcoin_consensus_encoding::Encodable for $name {
      type Encoder<'e> = $crate::__private::bitcoin_consensus_encoding::ArrayRefEncoder<'e, 32>;

      fn encoder(&self) -> Self::Encoder<'_> {
        $crate::__private::bitcoin_consensus_encoding::ArrayRefEncoder::without_length_prefix(
          self.0.as_bytes(),
        )
      }
    }

    impl $crate::__private::bitcoin_consensus_encoding::Decodable for $name {
      type Decoder = $crate::util::Hash256TypeDecoder<$name>;
      fn decoder() -> Self::Decoder {
        $crate::util::Hash256TypeDecoder::new()
      }
    }
  };
}

/// Generic decoder for hash256 newtypes.
#[derive(Clone, Debug)]
pub struct Hash256TypeDecoder<T>(
  bitcoin_consensus_encoding::ArrayDecoder<32>,
  core::marker::PhantomData<T>,
);

impl<T> Hash256TypeDecoder<T> {
  /// Constructs a new decoder.
  pub const fn new() -> Self {
    Self(
      bitcoin_consensus_encoding::ArrayDecoder::new(),
      core::marker::PhantomData,
    )
  }
}

impl<T> Default for Hash256TypeDecoder<T> {
  fn default() -> Self {
    Self::new()
  }
}

/// Decode error for hash256 newtypes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Hash256TypeDecoderError(pub bitcoin_consensus_encoding::UnexpectedEofError);

impl core::fmt::Display for Hash256TypeDecoderError {
  fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
    write!(f, "hash256 type decode: {}", self.0)
  }
}

impl<T> bitcoin_consensus_encoding::Decoder for Hash256TypeDecoder<T>
where
  T: From<[u8; 32]>,
{
  type Output = T;
  type Error = Hash256TypeDecoderError;

  #[inline]
  fn push_bytes(&mut self, bytes: &mut &[u8]) -> Result<bool, Self::Error> {
    self.0.push_bytes(bytes).map_err(Hash256TypeDecoderError)
  }

  #[inline]
  fn end(self) -> Result<Self::Output, Self::Error> {
    self.0.end().map(T::from).map_err(Hash256TypeDecoderError)
  }

  #[inline]
  fn read_limit(&self) -> usize {
    self.0.read_limit()
  }
}
