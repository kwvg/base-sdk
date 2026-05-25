//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Hash newtype macros.

/// Generates `Codec` + `Encodable` + `Decodable` for hash newtypes.
#[macro_export]
macro_rules! impl_hash {
  ($base:ty, $($name:ident),* $(,)?) => { $(
    impl dash_types::codec::Codec for $name {
      fn decode(
        data: &mut &[u8],
      ) -> Result<Self, dash_types::codec::DecodeError> {
        dash_types::codec::take::<{ <$base>::LEN }>(data)
          .map(Self::from_bytes)
      }

      fn encode(&self, buf: &mut ::alloc::vec::Vec<u8>) {
        buf.extend_from_slice(self.as_bytes());
      }
    }

    dash_types::impl_type!($name);
  )* };
}

/// Generates a newtype wrapping a hash base type with full trait
/// implementations and consensus encoding support.
#[macro_export]
macro_rules! make_hash {
  (
    $base:ty,
    $(#[$attr:meta])*
    $name:ident
  ) => {
    $(#[$attr])*
    #[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    #[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
    #[cfg_attr(feature = "serde", serde(transparent))]
    pub struct $name($base);

    impl $name {
      /// The all-zeros (null) hash.
      pub const ZERO: Self = Self(<$base>::ZERO);

      /// Wrap raw little-endian bytes into a hash.
      #[inline]
      pub const fn from_bytes(bytes: [u8; { <$base>::LEN }]) -> Self {
        Self(<$base>::from_bytes(bytes))
      }

      /// Return the raw little-endian bytes.
      #[inline]
      pub const fn to_bytes(self) -> [u8; { <$base>::LEN }] {
        self.0.to_bytes()
      }

      /// Borrow the raw little-endian bytes.
      #[inline]
      pub const fn as_bytes(&self) -> &[u8; { <$base>::LEN }] {
        self.0.as_bytes()
      }

      /// Construct from big-endian bytes (consensus display order).
      #[inline]
      pub const fn new(be: [u8; { <$base>::LEN }]) -> Self {
        Self(<$base>::new(be))
      }

      /// Returns `true` if every byte is zero.
      #[inline]
      pub const fn is_null(&self) -> bool {
        self.0.is_null()
      }

      /// Parse from a big-endian hex string.
      #[inline]
      pub fn from_hex(s: &str) -> Result<Self, $crate::ParseHexError> {
        <$base>::from_hex(s).map(Self)
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

    impl From<[u8; { <$base>::LEN }]> for $name {
      #[inline]
      fn from(bytes: [u8; { <$base>::LEN }]) -> Self { Self::from_bytes(bytes) }
    }

    impl From<$name> for [u8; { <$base>::LEN }] {
      #[inline]
      fn from(h: $name) -> Self { h.to_bytes() }
    }

    impl From<$base> for $name {
      #[inline]
      fn from(h: $base) -> Self { Self(h) }
    }

    impl From<$name> for $base {
      #[inline]
      fn from(h: $name) -> Self { h.0 }
    }

    impl AsRef<[u8]> for $name {
      #[inline]
      fn as_ref(&self) -> &[u8] { self.0.as_ref() }
    }

    impl AsRef<[u8; { <$base>::LEN }]> for $name {
      #[inline]
      fn as_ref(&self) -> &[u8; { <$base>::LEN }] { self.0.as_bytes() }
    }

    $crate::impl_hash!($base, $name);
  };
}

/// Convenience alias: generates a `Hash256`-based newtype.
#[macro_export]
macro_rules! make_hash256 {
  ($(#[$attr:meta])* $name:ident) => {
    $crate::make_hash!($crate::Hash256, $(#[$attr])* $name);
  };
}
