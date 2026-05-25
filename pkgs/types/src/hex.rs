//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Fixed-size byte newtype macros.

/// Generates `Codec` + `Encodable` + `Decodable` for a fixed-size
/// byte newtype that implements `From<[u8; N]>` and `as_bytes()`.
#[macro_export]
macro_rules! impl_bytes {
  ($n:literal, $($name:ident),* $(,)?) => { $(
    impl $crate::codec::Codec for $name {
      fn decode(
        data: &mut &[u8],
      ) -> Result<Self, $crate::codec::DecodeError> {
        $crate::codec::take::<$n>(data).map(Self::from)
      }

      fn encode(&self, buf: &mut ::alloc::vec::Vec<u8>) {
        buf.extend_from_slice(self.as_bytes());
      }
    }

    $crate::impl_type!($name);
  )* };
}

/// Generates a fixed-size byte newtype with consensus encoding traits and
/// standard trait implementations.
#[macro_export]
macro_rules! make_bytes {
  (
    $(#[$attr:meta])*
    $name:ident, $n:literal, $serde_with:literal
  ) => {
    $(#[$attr])*
    #[derive(Clone, Copy, PartialEq, Eq, Hash)]
    #[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
    #[cfg_attr(feature = "serde", serde(transparent))]
    pub struct $name(
      #[cfg_attr(feature = "serde", serde(with = $serde_with))]
      pub [u8; $n],
    );

    impl Default for $name {
      fn default() -> Self { Self([0u8; $n]) }
    }

    impl $name {
      /// Returns the inner byte array.
      pub const fn to_bytes(self) -> [u8; $n] {
        self.0
      }

      /// Borrows the inner byte array.
      pub const fn as_bytes(&self) -> &[u8; $n] {
        &self.0
      }

      /// Returns `true` when every byte is zero.
      pub fn is_null(&self) -> bool {
        self.0.iter().all(|&b| b == 0)
      }
    }

    impl From<[u8; $n]> for $name {
      fn from(bytes: [u8; $n]) -> Self { Self(bytes) }
    }

    impl From<$name> for [u8; $n] {
      fn from(val: $name) -> Self { val.0 }
    }

    impl AsRef<[u8]> for $name {
      fn as_ref(&self) -> &[u8] { &self.0 }
    }

    impl AsRef<[u8; $n]> for $name {
      fn as_ref(&self) -> &[u8; $n] { &self.0 }
    }

    impl core::fmt::Debug for $name {
      fn fmt(
        &self,
        f: &mut core::fmt::Formatter<'_>,
      ) -> core::fmt::Result {
        write!(f, "{}(", stringify!($name))?;
        for byte in &self.0 {
          write!(f, "{:02x}", byte)?;
        }
        write!(f, ")")
      }
    }

    impl core::fmt::Display for $name {
      fn fmt(
        &self,
        f: &mut core::fmt::Formatter<'_>,
      ) -> core::fmt::Result {
        for byte in &self.0 {
          write!(f, "{:02x}", byte)?;
        }
        Ok(())
      }
    }

    $crate::impl_bytes!($n, $name);
  };
}

/// Wire-order hex for `Vec<u8>` and fixed-size byte arrays.
///
/// Use with `#[serde(with = "dash_types::serialize::hex")]` on
/// `Vec<u8>` fields. For fixed-size byte arrays use a sub-module
/// (e.g. `hex::w16` for `[u8; 16]`).
#[cfg(feature = "serde")]
pub mod serde {
  use crate::prelude::*;

  use hex_conservative::{DisplayHex, FromHex};

  /// Serializes bytes as a wire-order hex string.
  pub fn serialize<S: ::serde::Serializer>(data: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
    serializer.serialize_str(&data.to_lower_hex_string())
  }

  /// Deserializes a hex string into bytes.
  pub fn deserialize<'de, D: ::serde::Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
    let s = <String as ::serde::Deserialize>::deserialize(deserializer)?;
    Vec::<u8>::from_hex(&s).map_err(::serde::de::Error::custom)
  }

  macro_rules! define_fixed {
    ($mod_name:ident, $n:literal) => {
      #[doc = concat!("Wire-order hex for `[u8; ", stringify!($n), "]`.")]
      pub mod $mod_name {
        use super::*;

        /// Serializes as a wire-order hex string.
        pub fn serialize<S: ::serde::Serializer>(data: &[u8; $n], serializer: S) -> Result<S::Ok, S::Error> {
          serializer.serialize_str(&data.to_lower_hex_string())
        }

        /// Deserializes a hex string into the array.
        pub fn deserialize<'de, D: ::serde::Deserializer<'de>>(deserializer: D) -> Result<[u8; $n], D::Error> {
          let s = <String as ::serde::Deserialize>::deserialize(deserializer)?;
          <[u8; $n]>::from_hex(&s).map_err(::serde::de::Error::custom)
        }
      }
    };
  }

  define_fixed!(w16, 16);
  define_fixed!(w20, 20);
  define_fixed!(w33, 33);
  define_fixed!(w48, 48);
  define_fixed!(w64, 64);
  define_fixed!(w96, 96);
}
