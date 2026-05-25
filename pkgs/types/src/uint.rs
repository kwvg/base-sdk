//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Fixed-size integer newtype macros.

/// Generates `Codec` + `Encodable` + `Decodable` + serde for a type
/// that already implements `NumCodec<$uint>`.
#[macro_export]
macro_rules! impl_num {
  ($name:tt, u8)  => { $crate::impl_num!(@codec $name, u8, 1); };
  ($name:tt, u16) => { $crate::impl_num!(@codec $name, u16, 2); };
  ($name:tt, u32) => { $crate::impl_num!(@codec $name, u32, 4); };
  ($name:tt, u64) => { $crate::impl_num!(@codec $name, u64, 8); };
  (@codec $name:ty, $uint:ty, $n:literal) => {
    impl $crate::codec::Codec for $name {
      fn decode(
        data: &mut &[u8],
      ) -> Result<Self, $crate::codec::DecodeError> {
        $crate::codec::take::<$n>(data).map(|b| {
          <Self as $crate::codec::NumCodec<$uint>>::from_base(
            <$uint>::from_le_bytes(b),
          )
        })
      }

      fn encode(&self, buf: &mut ::alloc::vec::Vec<u8>) {
        buf.extend_from_slice(
          &<Self as $crate::codec::NumCodec<$uint>>::to_base(self)
            .to_le_bytes(),
        );
      }
    }

    $crate::impl_type!($name);

    #[cfg(feature = "serde")]
    impl ::serde::Serialize for $name {
      fn serialize<S: ::serde::Serializer>(
        &self, serializer: S,
      ) -> Result<S::Ok, S::Error> {
        ::serde::Serialize::serialize(
          &<Self as $crate::codec::NumCodec<$uint>>::to_base(self),
          serializer,
        )
      }
    }

    #[cfg(feature = "serde")]
    impl<'de> ::serde::Deserialize<'de> for $name {
      fn deserialize<D: ::serde::Deserializer<'de>>(
        deserializer: D,
      ) -> Result<Self, D::Error> {
        <$uint as ::serde::Deserialize>::deserialize(deserializer)
          .map(<Self as $crate::codec::NumCodec<$uint>>::from_base)
      }
    }
  };
}

/// Generates a fixed-size integer newtype with consensus encoding traits and
/// standard trait implementations.
#[macro_export]
macro_rules! make_num {
  (
    $(#[$attr:meta])*
    $name:ident, $uint:tt, $n:literal
  ) => {
    $(#[$attr])*
    #[derive(Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
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

    impl $crate::codec::NumCodec<$uint> for $name {
      fn from_base(v: $uint) -> Self {
        Self(v)
      }

      fn to_base(&self) -> $uint {
        self.0
      }
    }

    $crate::impl_num!($name, $uint);
  };
}
