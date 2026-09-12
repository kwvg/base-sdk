//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Hash newtype macros.

/// dash-num's [`cfg_codec!`](dash_types::cfg_codec), keyed to `dash-num/codec`
/// (this crate) rather than `dash-types/codec`.
///
/// `{ .. } else { .. }` picks between two bodies rather than emitting one
/// conditionally, for an item that exists either way.
#[cfg(feature = "codec")]
#[doc(hidden)]
#[macro_export]
macro_rules! cfg_codec {
  ({$($with:tt)*} else {$($without:tt)*}) => { $($with)* };
  ($($item:tt)*) => { $($item)* };
}

#[cfg(not(feature = "codec"))]
#[doc(hidden)]
#[macro_export]
macro_rules! cfg_codec {
  ({$($with:tt)*} else {$($without:tt)*}) => { $($without)* };
  ($($item:tt)*) => {};
}

/// dash-num's [`cfg_serde!`](dash_types::cfg_serde), keyed to `dash-num/serde`
/// (this crate) rather than `dash-types/serde`.
#[cfg(feature = "serde")]
#[doc(hidden)]
#[macro_export]
macro_rules! cfg_serde {
  ($($item:tt)*) => { $($item)* };
}

#[cfg(not(feature = "serde"))]
#[doc(hidden)]
#[macro_export]
macro_rules! cfg_serde {
  ($($item:tt)*) => {};
}

/// Generates `BaseCodec` + `Encode` + `Decode` for hash newtypes.
#[macro_export]
macro_rules! impl_hash {
  ($base:ty, $($name:ident),* $(,)?) => { $( $crate::cfg_codec! {
    impl $crate::__private::dash_types::codec::BaseCodec for $name {
      fn decode(
        data: &mut &[u8],
      ) -> Result<Self, $crate::__private::dash_types::codec::DecodeError> {
        $crate::__private::dash_types::codec::take::<{ <$base>::LEN }>(data)
          .map(Self::from_bytes)
      }

      fn encode(&self, buf: &mut impl $crate::__private::dash_types::codec::EncodeBuf) {
        buf.extend_from_slice(self.as_bytes());
      }
    }

    $crate::__private::dash_types::impl_type!($name);
  } )* };
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
    $crate::cfg_codec! {
      {
        $(#[$attr])*
        #[derive(
          Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash,
          $crate::__private::dash_types::type_id::TypeId,
        )]
        pub struct $name($base);
      } else {
        $(#[$attr])*
        #[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name($base);
      }
    }

    $crate::cfg_serde! {
      impl $crate::__private::serde::Serialize for $name {
        fn serialize<S: $crate::__private::serde::Serializer>(
          &self, serializer: S,
        ) -> Result<S::Ok, S::Error> {
          $crate::__private::serde::Serialize::serialize(&self.0, serializer)
        }
      }

      impl<'de> $crate::__private::serde::Deserialize<'de> for $name {
        fn deserialize<D: $crate::__private::serde::Deserializer<'de>>(
          deserializer: D,
        ) -> Result<Self, D::Error> {
          <$base as $crate::__private::serde::Deserialize>::deserialize(deserializer).map(Self)
        }
      }
    }

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

    impl ::core::fmt::Display for $name {
      fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
        ::core::fmt::Display::fmt(&self.0, f)
      }
    }

    impl ::core::fmt::Debug for $name {
      fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
        write!(f, "{}({})", stringify!($name), self.0)
      }
    }

    impl ::core::str::FromStr for $name {
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
