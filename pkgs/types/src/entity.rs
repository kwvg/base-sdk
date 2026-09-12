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

/// Declares a fixed-size byte newtype over `[u8; N]` with the `from_bytes` /
/// `to_bytes` / `as_bytes` accessors.
///
/// Invokes [`impl_bytes!`](crate::impl_bytes) and
/// [`derive_bytes!`](crate::derive_bytes). A newtype that needs a validating
/// constructor, a scheme tag, or its own trait set should define itself and
/// invoke those macros manually.
#[macro_export]
macro_rules! make_bytes {
  (
    $(#[$attr:meta])*
    $name:ident, $n:literal
  ) => {
    $(#[$attr])*
    #[derive($crate::type_id::TypeId)]
    pub struct $name(pub [u8; $n]);

    $crate::impl_bytes!($name, $n);

    $crate::derive_bytes!($name, $n);

    impl $name {
      /// Wraps raw bytes without validation.
      pub const fn from_bytes(bytes: [u8; $n]) -> Self {
        Self(bytes)
      }

      /// Returns the inner byte array.
      pub const fn to_bytes(self) -> [u8; $n] {
        self.0
      }

      /// Borrows the inner byte array.
      pub const fn as_bytes(&self) -> &[u8; $n] {
        &self.0
      }
    }
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
