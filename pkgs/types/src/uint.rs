//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Fixed-size integer newtype macro and decoder.

/// Types that can be represented as an unsigned integer for serialization.
pub trait AsUint<N> {
  /// Returns the integer representation.
  fn as_uint(&self) -> N;
}

/// Types that can be constructed from an unsigned integer during
/// deserialization.
pub trait TryFromUint<N>: Sized {
  /// The error type returned on failure.
  type Err: core::fmt::Display;

  /// Construct from the integer value.
  fn try_from_uint(v: N) -> Result<Self, Self::Err>;
}

/// Generates a fixed-size integer newtype with consensus encoding traits and
/// standard trait implementations.
#[macro_export]
macro_rules! make_uint {
  (
    $(#[$attr:meta])*
    $name:ident, $uint:ty, $n:literal
  ) => {
    $(#[$attr])*
    #[derive(Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
    #[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
    #[cfg_attr(feature = "serde", serde(transparent))]
    pub struct $name(pub $uint);

    impl $name {
      /// Constructs from the raw integer value.
      pub const fn new(v: $uint) -> Self {
        Self(v)
      }

      /// Returns the inner integer value.
      pub const fn value(self) -> $uint {
        self.0
      }
    }

    impl From<$uint> for $name {
      fn from(v: $uint) -> Self { Self(v) }
    }

    impl From<$name> for $uint {
      fn from(v: $name) -> Self { v.0 }
    }

    impl From<[u8; $n]> for $name {
      fn from(bytes: [u8; $n]) -> Self {
        Self(<$uint>::from_le_bytes(bytes))
      }
    }

    impl core::fmt::Debug for $name {
      fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}({})", stringify!($name), self.0)
      }
    }

    impl core::fmt::Display for $name {
      fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        core::fmt::Display::fmt(&self.0, f)
      }
    }

    impl $crate::__private::bitcoin_consensus_encoding::Encodable for $name {
      type Encoder<'e> = $crate::__private::bitcoin_consensus_encoding::ArrayEncoder<$n>;

      fn encoder(&self) -> Self::Encoder<'_> {
        $crate::__private::bitcoin_consensus_encoding::ArrayEncoder::without_length_prefix(
          self.0.to_le_bytes(),
        )
      }
    }

    impl $crate::__private::bitcoin_consensus_encoding::Decodable for $name {
      type Decoder = $crate::__private::ByteTypeDecoder<$name, $n>;
      fn decoder() -> Self::Decoder {
        $crate::__private::ByteTypeDecoder::new()
      }
    }
  };
}

/// Unsigned integer serialization for types implementing [`AsUint`] and
/// [`TryFromUint`].
#[cfg(feature = "serde")]
pub mod serde {
  use super::{AsUint, TryFromUint};

  macro_rules! define_fixed {
    ($mod_name:ident, $uint:ty) => {
      #[doc = concat!("Serialize/deserialize via `", stringify!($uint), "`.")]
      pub mod $mod_name {
        use super::*;

        #[doc = concat!("Serializes the value as a `", stringify!($uint), "`.")]
        pub fn serialize<T: AsUint<$uint>, S: ::serde::Serializer>(val: &T, serializer: S) -> Result<S::Ok, S::Error> {
          ::serde::Serialize::serialize(&val.as_uint(), serializer)
        }

        #[doc = concat!("Deserializes a `", stringify!($uint), "` into the target type.")]
        pub fn deserialize<'de, T: TryFromUint<$uint>, D: ::serde::Deserializer<'de>>(
          deserializer: D,
        ) -> Result<T, D::Error> {
          let v = <$uint as ::serde::Deserialize>::deserialize(deserializer)?;
          T::try_from_uint(v).map_err(::serde::de::Error::custom)
        }
      }
    };
  }

  define_fixed!(w8, u8);
  define_fixed!(w16, u16);
  define_fixed!(w32, u32);
  define_fixed!(w64, u64);
}
