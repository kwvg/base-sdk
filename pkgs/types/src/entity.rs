//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Buffered codec implementation.

#[cfg(feature = "codec")]
use crate::codec::DecodeError;
#[cfg(feature = "codec")]
use crate::prelude::*;

#[cfg(feature = "codec")]
use bitcoin_consensus_encoding::{Decoder, Encoder};

#[cfg(feature = "codec")]
use core::convert::Infallible;
#[cfg(feature = "codec")]
use core::fmt;

#[cfg(feature = "codec")]
/// Maximum serialized object size (32 MiB).
pub const MAX_SER_SIZE: usize = 0x0200_0000;

#[cfg(feature = "codec")]
/// An encoder that wraps a pre-built byte vector.
#[derive(Clone)]
pub struct VecEncoder {
  data: Vec<u8>,
  done: bool,
}

#[cfg(feature = "codec")]
impl VecEncoder {
  /// Creates a new encoder wrapping the given bytes.
  pub fn new(data: Vec<u8>) -> Self {
    Self { data, done: false }
  }
}

#[cfg(feature = "codec")]
impl fmt::Debug for VecEncoder {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.debug_struct("VecEncoder")
      .field("len", &self.data.len())
      .field("done", &self.done)
      .finish()
  }
}

#[cfg(feature = "codec")]
impl Encoder for VecEncoder {
  fn current_chunk(&self) -> &[u8] {
    if self.done {
      &[]
    } else {
      &self.data
    }
  }

  fn advance(&mut self) -> bool {
    if self.done {
      false
    } else {
      self.done = true;
      false
    }
  }
}

#[cfg(feature = "codec")]
/// A decoder that buffers all input and decodes in `end()`.
///
/// Wraps types with complex sequential decode logic (conditional fields,
/// version branching) that cannot be expressed as a composable push-decoder
/// without excessive boilerplate.
pub struct VecDecoder<T, E = Infallible> {
  buf: Vec<u8>,
  limit: usize,
  decode_fn: fn(&mut &[u8]) -> Result<T, DecodeError<E>>,
}

#[cfg(feature = "codec")]
impl<T, E> VecDecoder<T, E> {
  /// Creates a new decoder with the given decode function and
  /// maximum buffer size.
  pub const fn new(decode_fn: fn(&mut &[u8]) -> Result<T, DecodeError<E>>, limit: usize) -> Self {
    Self {
      buf: Vec::new(),
      limit,
      decode_fn,
    }
  }
}

#[cfg(feature = "codec")]
impl<T, E> fmt::Debug for VecDecoder<T, E> {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.debug_struct("VecDecoder")
      .field("buf_len", &self.buf.len())
      .field("limit", &self.limit)
      .finish()
  }
}

#[cfg(feature = "codec")]
impl<T, E> Clone for VecDecoder<T, E> {
  fn clone(&self) -> Self {
    Self {
      buf: self.buf.clone(),
      limit: self.limit,
      decode_fn: self.decode_fn,
    }
  }
}

#[cfg(feature = "codec")]
impl<T, E> Decoder for VecDecoder<T, E> {
  type Output = T;
  type Error = DecodeError<E>;

  fn push_bytes(&mut self, bytes: &mut &[u8]) -> Result<bool, Self::Error> {
    let remaining = self.limit.saturating_sub(self.buf.len());
    if remaining == 0 {
      return Ok(false);
    }
    let take = bytes.len().min(remaining);
    self.buf.extend_from_slice(&bytes[..take]);
    *bytes = &bytes[take..];
    Ok(true)
  }

  fn end(self) -> Result<Self::Output, Self::Error> {
    let mut cursor = &self.buf[..];
    let result = (self.decode_fn)(&mut cursor)?;
    if !cursor.is_empty() {
      return Err(DecodeError::TrailingBytes {
        remaining: cursor.len(),
      });
    }
    Ok(result)
  }

  fn read_limit(&self) -> usize {
    self.limit.saturating_sub(self.buf.len())
  }
}

/// Generates `Encode` + `Decode` for a `BaseCodec` implementor.
///
/// Stages through the growable [`VecEncoder`]/[`VecDecoder`] pair. For
/// secret material use [`impl_stype!`](crate::impl_stype) instead, which is
/// the same generator over the wiping fixed-width pair.
#[cfg(feature = "codec")]
#[macro_export]
macro_rules! impl_type {
  (@parse [$($impl_generics:tt)*] $ty:ty, $max:expr, $err:ty) => {
    impl<$($impl_generics)*> $crate::__private::bitcoin_consensus_encoding::Encode for $ty {
      type Encoder<'e> = $crate::VecEncoder;
      fn encoder(&self) -> Self::Encoder<'_> {
        let mut buf = ::alloc::vec::Vec::new();
        $crate::codec::BaseCodec::encode(self, &mut buf);
        $crate::VecEncoder::new(buf)
      }
    }

    impl<$($impl_generics)*> $crate::__private::bitcoin_consensus_encoding::Decode for $ty {
      type Decoder = $crate::VecDecoder<$ty, $err>;
      fn decoder() -> Self::Decoder {
        $crate::VecDecoder::new(<$ty as $crate::codec::BaseCodec<$err>>::decode, $max)
      }
    }
  };
  (@parse [$($impl_generics:tt)*] $ty:ty, $max:expr) => {
    $crate::impl_type!(
      @parse [$($impl_generics)*] $ty,
      $max,
      ::core::convert::Infallible
    );
  };
  (@parse [$($impl_generics:tt)*] $ty:ty) => {
    $crate::impl_type!(@parse [$($impl_generics)*] $ty, $crate::MAX_SER_SIZE);
  };
  (for[$($generic:tt)*] $($args:tt)*) => {
    $crate::impl_type!(@parse [$($generic)*] $($args)*);
  };
  ($($args:tt)*) => {
    $crate::impl_type!(@parse [] $($args)*);
  };
}

/// Generates `BaseCodec` + `Encode` + `Decode` + `From<[u8; N]>` for a
/// fixed-size byte newtype, expressed only through `from_bytes` / `as_bytes`.
///
/// Staged through the growable [`VecEncoder`]. For a newtype whose contents
/// are secret use [`impl_sbytes!`](crate::impl_sbytes).
#[cfg(feature = "codec")]
#[macro_export]
macro_rules! impl_bytes {
  // Shared by `impl_bytes!` and `impl_sbytes!`, only the encoder pair differs.
  (@codec [$($g:tt)*] $ty:ty, $n:expr) => {
    impl<$($g)*> $crate::codec::BaseCodec for $ty {
      fn decode(
        data: &mut &[u8],
      ) -> Result<Self, $crate::codec::DecodeError> {
        $crate::codec::take::<$n>(data).map(Self::from_bytes)
      }

      fn encode(&self, buf: &mut impl $crate::codec::EncodeBuf) {
        buf.extend_from_slice(self.as_bytes());
      }
    }

    impl<$($g)*> ::core::convert::From<[u8; $n]> for $ty {
      fn from(bytes: [u8; $n]) -> Self { Self::from_bytes(bytes) }
    }
  };
  (@parse [$($g:tt)*] $ty:ty, $n:expr) => {
    $crate::impl_bytes!(@codec [$($g)*] $ty, $n);

    $crate::impl_type!(@parse [$($g)*] $ty, $n);
  };
  (for[$($generic:tt)*] $($args:tt)*) => {
    $crate::impl_bytes!(@parse [$($generic)*] $($args)*);
  };
  ($($args:tt)*) => {
    $crate::impl_bytes!(@parse [] $($args)*);
  };
}

/// The standard trait set for a fixed-size byte newtype, expressed only
/// through `from_bytes` / `as_bytes`.
///
/// Emits `Clone`, `Copy`, `Default`, `Eq`, `PartialEq`, `Ord`, `PartialOrd`,
/// `Hash`, `is_null`, `AsRef<[u8]>`, `AsRef<[u8; N]>`, `From<Self> for
/// [u8; N]`, a hex `Debug`/`Display`, and the hex `serde` pair.
///
/// A trailing `rev` renders the hex in reverse storage order, the default `fwd`
/// renders storage order.
///
/// For a newtype holding secrets use [`derive_sbytes!`](crate::derive_sbytes),
/// which withholds everything that would read or copy out the plaintext.
#[macro_export]
macro_rules! derive_bytes {
  (@parse [$($g:tt)*] $ty:ty, $n:expr, $rev:expr) => {
    impl<$($g)*> ::core::clone::Clone for $ty {
      fn clone(&self) -> Self { *self }
    }

    impl<$($g)*> ::core::marker::Copy for $ty {}

    impl<$($g)*> ::core::default::Default for $ty {
      fn default() -> Self { Self::from_bytes([0u8; $n]) }
    }

    impl<$($g)*> ::core::cmp::Eq for $ty {}

    impl<$($g)*> ::core::cmp::PartialEq for $ty {
      fn eq(&self, other: &Self) -> bool { self.as_bytes() == other.as_bytes() }
    }

    impl<$($g)*> ::core::cmp::Ord for $ty {
      fn cmp(&self, other: &Self) -> ::core::cmp::Ordering {
        self.as_bytes().cmp(other.as_bytes())
      }
    }

    impl<$($g)*> ::core::cmp::PartialOrd for $ty {
      fn partial_cmp(&self, other: &Self) -> ::core::option::Option<::core::cmp::Ordering> {
        ::core::option::Option::Some(::core::cmp::Ord::cmp(self, other))
      }
    }

    impl<$($g)*> ::core::hash::Hash for $ty {
      fn hash<H: ::core::hash::Hasher>(&self, state: &mut H) {
        ::core::hash::Hash::hash(self.as_bytes(), state);
      }
    }

    impl<$($g)*> ::core::convert::AsRef<[u8]> for $ty {
      fn as_ref(&self) -> &[u8] { self.as_bytes() }
    }

    impl<$($g)*> ::core::convert::AsRef<[u8; $n]> for $ty {
      fn as_ref(&self) -> &[u8; $n] { self.as_bytes() }
    }

    impl<$($g)*> ::core::convert::From<$ty> for [u8; $n] {
      fn from(val: $ty) -> Self { *val.as_bytes() }
    }

    impl<$($g)*> $ty {
      /// Returns `true` when every byte is zero.
      pub fn is_null(&self) -> bool { self.as_bytes().iter().all(|&b| b == 0) }
    }

    impl<$($g)*> ::core::fmt::Debug for $ty {
      fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
        $crate::qtypestr(f, ::core::any::type_name::<Self>())?;
        f.write_str("(")?;
        ::core::fmt::Display::fmt(self, f)?;
        f.write_str(")")
      }
    }

    $crate::derive_bytes!(@hex [$($g)*] $ty, $n, $rev);
  };
  (@order [$($g:tt)*] $ty:ty, $n:expr, fwd) => {
    $crate::derive_bytes!(@parse [$($g)*] $ty, $n, false);
  };
  (@order [$($g:tt)*] $ty:ty, $n:expr, rev) => {
    $crate::derive_bytes!(@parse [$($g)*] $ty, $n, true);
  };
  (@hex [$($g:tt)*] $ty:ty, $n:expr, $rev:expr) => {
    impl<$($g)*> ::core::fmt::Display for $ty {
      fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
        let bytes = self.as_bytes();
        for i in 0..$n {
          let byte = if $rev { bytes[$n - 1 - i] } else { bytes[i] };
          ::core::write!(f, "{byte:02x}")?;
        }
        ::core::result::Result::Ok(())
      }
    }

    $crate::cfg_serde! {
      impl<$($g)*> $crate::__private::serde::Serialize for $ty {
        fn serialize<Z>(&self, serializer: Z) -> Result<Z::Ok, Z::Error>
        where
          Z: $crate::__private::serde::Serializer,
        {
          serializer.serialize_str(&::alloc::format!("{self}"))
        }
      }

      impl<'de, $($g)*> $crate::__private::serde::Deserialize<'de> for $ty {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
          D: $crate::__private::serde::Deserializer<'de>,
        {
          use $crate::__private::serde::de::Error as _;
          let s = <::alloc::string::String as $crate::__private::serde::Deserialize>::deserialize(deserializer)?;
          let mut bytes = <[u8; $n] as $crate::__private::hex_conservative::FromHex>::from_hex(&s)
            .map_err(D::Error::custom)?;
          if $rev {
            bytes.reverse();
          }
          ::core::result::Result::Ok(Self::from_bytes(bytes))
        }
      }
    }
  };
  (for[$($generic:tt)*] $ty:ty, $n:expr, $order:tt) => {
    $crate::derive_bytes!(@order [$($generic)*] $ty, $n, $order);
  };
  (for[$($generic:tt)*] $ty:ty, $n:expr) => {
    $crate::derive_bytes!(@order [$($generic)*] $ty, $n, fwd);
  };
  ($ty:ty, $n:expr, $order:tt) => {
    $crate::derive_bytes!(@order [] $ty, $n, $order);
  };
  ($ty:ty, $n:expr) => {
    $crate::derive_bytes!(@order [] $ty, $n, fwd);
  };
}

/// Declares a fixed-size byte newtype over `[u8; N]` with the `from_bytes` /
/// `to_bytes` / `as_bytes` accessors.
///
/// A `for[..]` prefix takes type parameters, held in a `PhantomData` beside
/// the bytes, for a type that utilizes parameters for tagging without mutating
/// the inner structure.
///
/// Invokes [`impl_bytes!`](crate::impl_bytes) and
/// [`derive_bytes!`](crate::derive_bytes). A newtype that needs a validating
/// constructor or its own trait set should define itself and invoke those
/// macros manually.
#[macro_export]
macro_rules! make_bytes {
  (@struct [$($g:tt)*] {$($attr:tt)*} $(#[$derive:meta])? $name:ident $(<$($param:ident),+>)?, $n:expr) => {
    $($attr)*
    $(#[$derive])?
    // A plain bag gets an empty `<>`, legal and invisible in rustdoc.
    pub struct $name<$($g)*> {
      inner: [u8; $n],
      $(_marker: ::core::marker::PhantomData<fn() -> ($($param,)+)>,)?
    }
  };
  (@parse [$($g:tt)*] $attrs:tt $name:ident $(<$($param:ident),+>)?, $n:expr) => {
    $crate::cfg_codec! {
      {
        $crate::make_bytes!(
          @struct [$($g)*] $attrs #[derive($crate::type_id::TypeId)] $name $(<$($param),+>)?, $n
        );

        $crate::impl_bytes!(@parse [$($g)*] $name $(<$($param),+>)?, $n);
      } else {
        $crate::make_bytes!(@struct [$($g)*] $attrs $name $(<$($param),+>)?, $n);
      }
    }

    $crate::derive_bytes!(@order [$($g)*] $name $(<$($param),+>)?, $n, fwd);

    impl<$($g)*> $name $(<$($param),+>)? {
      /// Wraps raw bytes without validation.
      pub const fn from_bytes(bytes: [u8; $n]) -> Self {
        Self {
          inner: bytes,
          $(_marker: ::core::marker::PhantomData::<fn() -> ($($param,)+)>,)?
        }
      }

      /// Returns the inner byte array.
      pub const fn to_bytes(self) -> [u8; $n] {
        self.inner
      }

      /// Borrows the inner byte array.
      pub const fn as_bytes(&self) -> &[u8; $n] {
        &self.inner
      }
    }
  };
  ($(#[$attr:meta])* for[$($generic:tt)*] $name:ident<$($param:ident),+>, $($args:tt)*) => {
    $crate::make_bytes!(@parse [$($generic)*] {$(#[$attr])*} $name<$($param),+>, $($args)*);
  };
  ($(#[$attr:meta])* $name:ident, $($args:tt)*) => {
    $crate::make_bytes!(@parse [] {$(#[$attr])*} $name, $($args)*);
  };
}

/// Delegates `BaseCodec`, `Hashable`, and `impl_type!` through another type.
///
/// Decode is fallible: `$bytes` is unvalidated, so `TryFrom<$bytes>` guards
/// the operational type. Encode is not: the value is already valid, so
/// `From<&$ops> for $bytes` must exist and must be infallible, since a failing
/// encode could only emit nothing or a placeholder, corrupting the wire image.
///
/// `$max` bounds the `impl_type!` decoder buffer to the wrapped type's own
/// maximum encoded length. For a secret wire image use
/// [`dlgt_scodec!`](crate::dlgt_scodec).
#[cfg(feature = "codec")]
#[macro_export]
macro_rules! dlgt_codec {
  // Shared by `dlgt_codec!` and `dlgt_scodec!`, only the encoder pair differs.
  (@delegate [$($impl_generics:tt)*] $ops:ty => $bytes:ty, $hash:ty, $err:ty) => {
    impl<$($impl_generics)*> $crate::codec::BaseCodec<$err> for $ops {
      fn decode(data: &mut &[u8]) -> Result<Self, $crate::codec::DecodeError<$err>> {
        let inner = <$bytes as $crate::codec::BaseCodec>::decode(data).map_err(|e| e.lift())?;
        Self::try_from(inner).map_err($crate::codec::DecodeError::DecError)
      }

      fn encode(&self, buf: &mut impl $crate::codec::EncodeBuf) {
        $crate::codec::BaseCodec::encode(&<$bytes as ::core::convert::From<&Self>>::from(self), buf);
      }
    }

    impl<$($impl_generics)*> $crate::codec::Hashable for $ops {
      type Hash = $hash;

      fn hash(&self) -> $hash {
        $crate::codec::Hashable::hash(&<$bytes as ::core::convert::From<&Self>>::from(self))
      }
    }
  };
  (@parse [$($impl_generics:tt)*] $ops:ty => $bytes:ty, $hash:ty, $err:ty, $max:expr) => {
    $crate::dlgt_codec!(@delegate [$($impl_generics)*] $ops => $bytes, $hash, $err);

    $crate::impl_type!(@parse [$($impl_generics)*] $ops, $max, $err);
  };
  (for[$($generic:tt)*] $($args:tt)*) => {
    $crate::dlgt_codec!(@parse [$($generic)*] $($args)*);
  };
  ($($args:tt)*) => {
    $crate::dlgt_codec!(@parse [] $($args)*);
  };
}
