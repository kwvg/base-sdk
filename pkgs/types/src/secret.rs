//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Secret-holding codec implementation.

#[cfg(feature = "codec")]
use crate::codec::{DecodeError, EncodeBuf};

#[cfg(feature = "codec")]
use bitcoin_consensus_encoding::{Decoder, Encoder};
#[cfg(feature = "codec")]
use zeroize::Zeroize;

#[cfg(feature = "codec")]
use core::convert::Infallible;
#[cfg(feature = "codec")]
use core::fmt;

#[cfg(feature = "codec")]
/// Widest buffer [`ArrEncoder`] and [`ArrDecoder`] will wipe.
pub const MAX_ARR_SIZE: usize = 512;

#[cfg(feature = "codec")]
/// Fixed-size encode buffer backed by `[u8; N]`.
///
/// Implements [`Zeroize`] but has no `Drop`, so it does *not* wipe itself when
/// it goes out of scope. To hold secret material, wrap it in `Zeroizing` or
/// move it into [`ArrEncoder`] or [`ArrDecoder`], which wipe on drop.
///
/// # Panics
///
/// Writing more than `N` bytes (via the [`EncodeBuf`] impl) panics with an
/// index-out-of-bounds.
#[derive(Clone)]
pub struct ArrayBuf<const N: usize> {
  buf: [u8; N],
  len: usize,
}

#[cfg(feature = "codec")]
impl<const N: usize> ArrayBuf<N> {
  /// Creates an empty buffer.
  pub const fn new() -> Self {
    Self { buf: [0u8; N], len: 0 }
  }

  /// Borrows the written bytes.
  pub fn as_bytes(&self) -> &[u8] {
    &self.buf[..self.len]
  }

  /// Returns `true` when nothing has been written.
  pub const fn is_empty(&self) -> bool {
    self.len == 0
  }

  /// Number of bytes written so far.
  pub const fn len(&self) -> usize {
    self.len
  }

  /// Remaining writable capacity.
  pub const fn spare(&self) -> usize {
    N - self.len
  }

  /// Returns the written bytes as a fixed array.
  ///
  /// # Panics
  ///
  /// Panics if exactly `N` bytes were not written.
  pub fn into_array(self) -> [u8; N] {
    assert!(self.len == N, "expected {N} bytes, wrote {}", self.len);
    self.buf
  }
}

#[cfg(feature = "codec")]
impl<const N: usize> fmt::Debug for ArrayBuf<N> {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.debug_struct("ArrayBuf").field("len", &self.len).finish()
  }
}

#[cfg(feature = "codec")]
impl<const N: usize> Default for ArrayBuf<N> {
  fn default() -> Self {
    Self::new()
  }
}

#[cfg(feature = "codec")]
impl<const N: usize> EncodeBuf for ArrayBuf<N> {
  fn push(&mut self, byte: u8) {
    self.buf[self.len] = byte;
    self.len += 1;
  }

  fn extend_from_slice(&mut self, data: &[u8]) {
    self.buf[self.len..self.len + data.len()].copy_from_slice(data);
    self.len += data.len();
  }
}

#[cfg(feature = "codec")]
impl<const N: usize> Zeroize for ArrayBuf<N> {
  fn zeroize(&mut self) {
    self.buf.zeroize();
    self.len = 0;
  }
}

#[cfg(feature = "codec")]
/// An encoder for values whose encoded width is bounded at compile time.
///
/// Costs a byte-wise volatile write per byte of `N`, so it suits key material
/// and other small fixed records, not block-sized payloads. [`MAX_ARR_SIZE`]
/// caps `N` due to performance cost.
pub struct ArrEncoder<const N: usize> {
  data: ArrayBuf<N>,
  done: bool,
}

#[cfg(feature = "codec")]
impl<const N: usize> ArrEncoder<N> {
  /// Wraps a filled buffer.
  ///
  /// Refuses to compile when `N` exceeds [`MAX_ARR_SIZE`].
  pub const fn new(data: ArrayBuf<N>) -> Self {
    const { assert!(N <= MAX_ARR_SIZE, "unusually large zeroized buffer") };
    Self { data, done: false }
  }
}

#[cfg(feature = "codec")]
impl<const N: usize> fmt::Debug for ArrEncoder<N> {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.debug_struct("ArrEncoder")
      .field("len", &self.data.len())
      .field("done", &self.done)
      .finish()
  }
}

#[cfg(feature = "codec")]
impl<const N: usize> Drop for ArrEncoder<N> {
  fn drop(&mut self) {
    self.data.zeroize();
  }
}

#[cfg(feature = "codec")]
impl<const N: usize> Encoder for ArrEncoder<N> {
  fn current_chunk(&self) -> &[u8] {
    if self.done {
      &[]
    } else {
      self.data.as_bytes()
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
/// A decoder for values whose encoded width is bounded by `N`.
pub struct ArrDecoder<T, const N: usize, E = Infallible> {
  buf: ArrayBuf<N>,
  decode_fn: fn(&mut &[u8]) -> Result<T, DecodeError<E>>,
}

#[cfg(feature = "codec")]
impl<T, const N: usize, E> ArrDecoder<T, N, E> {
  /// Creates a decoder that accepts at most `N` bytes.
  ///
  /// Refuses to compile when `N` exceeds [`MAX_ARR_SIZE`].
  pub const fn new(decode_fn: fn(&mut &[u8]) -> Result<T, DecodeError<E>>) -> Self {
    const { assert!(N <= MAX_ARR_SIZE, "unusually large zeroized buffer") };
    Self {
      buf: ArrayBuf::new(),
      decode_fn,
    }
  }
}

#[cfg(feature = "codec")]
impl<T, const N: usize, E> fmt::Debug for ArrDecoder<T, N, E> {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.debug_struct("ArrDecoder")
      .field("buf_len", &self.buf.len())
      .field("limit", &N)
      .finish()
  }
}

#[cfg(feature = "codec")]
impl<T, const N: usize, E> Drop for ArrDecoder<T, N, E> {
  fn drop(&mut self) {
    self.buf.zeroize();
  }
}

#[cfg(feature = "codec")]
impl<T, const N: usize, E> Decoder for ArrDecoder<T, N, E> {
  type Output = T;
  type Error = DecodeError<E>;

  fn push_bytes(&mut self, bytes: &mut &[u8]) -> Result<bool, Self::Error> {
    let remaining = self.buf.spare();
    if remaining == 0 {
      return Ok(false);
    }
    let take = bytes.len().min(remaining);
    self.buf.extend_from_slice(&bytes[..take]);
    *bytes = &bytes[take..];
    Ok(true)
  }

  fn end(self) -> Result<Self::Output, Self::Error> {
    // Borrow rather than destructure: `Drop` wipes the buffer on the way out,
    // including on the early return below.
    let mut cursor = self.buf.as_bytes();
    let result = (self.decode_fn)(&mut cursor)?;
    if !cursor.is_empty() {
      return Err(DecodeError::TrailingBytes {
        remaining: cursor.len(),
      });
    }
    Ok(result)
  }

  fn read_limit(&self) -> usize {
    self.buf.spare()
  }
}

/// Generates `Encode` + `Decode` for a `BaseCodec` implementor whose
/// wire image is secret.
///
/// Stages through the wiping [`ArrEncoder`]/[`ArrDecoder`] pair, both sized by
/// `$n` and capped at [`MAX_ARR_SIZE`]. For public material use
/// [`impl_type!`](crate::impl_type), the same generator over the growable
/// pair.
#[cfg(feature = "codec")]
#[macro_export]
macro_rules! impl_stype {
  (@parse [$($impl_generics:tt)*] $ty:ty, $n:expr, $err:ty) => {
    impl<$($impl_generics)*> $crate::__private::bitcoin_consensus_encoding::Encode for $ty {
      type Encoder<'e> = $crate::ArrEncoder<{ $n }>;
      fn encoder(&self) -> Self::Encoder<'_> {
        let mut buf = $crate::ArrayBuf::<{ $n }>::new();
        <$ty as $crate::codec::BaseCodec<$err>>::encode(self, &mut buf);
        $crate::ArrEncoder::new(buf)
      }
    }

    impl<$($impl_generics)*> $crate::__private::bitcoin_consensus_encoding::Decode for $ty {
      type Decoder = $crate::ArrDecoder<$ty, { $n }, $err>;
      fn decoder() -> Self::Decoder {
        $crate::ArrDecoder::new(<$ty as $crate::codec::BaseCodec<$err>>::decode)
      }
    }
  };
  (@parse [$($impl_generics:tt)*] $ty:ty, $n:expr) => {
    $crate::impl_stype!(
      @parse [$($impl_generics)*] $ty,
      $n,
      ::core::convert::Infallible
    );
  };
  (@parse [$($impl_generics:tt)*] $ty:ty) => {
    ::core::compile_error!(concat!(
      "impl_stype! needs the fixed width of ", stringify!($ty), ": write impl_stype!(", stringify!($ty), ", N)"
    ));
  };
  (for[$($generic:tt)*] $($args:tt)*) => {
    $crate::impl_stype!(@parse [$($generic)*] $($args)*);
  };
  ($($args:tt)*) => {
    $crate::impl_stype!(@parse [] $($args)*);
  };
}

/// The secret counterpart to [`impl_bytes!`](crate::impl_bytes), for a
/// fixed-size byte newtype whose contents are key material.
///
/// Same `BaseCodec` and `From<[u8; N]>`, staged through the wiping
/// [`ArrEncoder`] rather than the growable [`VecEncoder`](crate::VecEncoder).
#[cfg(feature = "codec")]
#[macro_export]
macro_rules! impl_sbytes {
  (@parse [$($g:tt)*] $ty:ty, $n:expr) => {
    $crate::impl_bytes!(@codec [$($g)*] $ty, $n);

    $crate::impl_stype!(@parse [$($g)*] $ty, $n);
  };
  (for[$($generic:tt)*] $($args:tt)*) => {
    $crate::impl_sbytes!(@parse [$($generic)*] $($args)*);
  };
  ($($args:tt)*) => {
    $crate::impl_sbytes!(@parse [] $($args)*);
  };
}

/// The secret counterpart to [`derive_bytes!`](crate::derive_bytes), for a
/// fixed-size byte newtype holding key material.
///
/// Emits `Drop`, `ZeroizeOnDrop`, `is_null`, the `AsRef` pair, and a redacting
/// `Debug`/`Display`. `Zeroize`, `Clone` and `Eq`/`PartialEq` are left to the
/// type: only it knows which fields are secret, and equality must be
/// constant-time.
///
/// Withholds `Copy`, `Default`, `Ord`/`PartialOrd`/`Hash`, `From<Self> for
/// [u8; N]` and the hex `serde` pair, each because it either escapes the wipe
/// or reads the plaintext. Do *not* implement them.
#[macro_export]
macro_rules! derive_sbytes {
  (@parse [$($g:tt)*] $ty:ty, $n:expr) => {
    impl<$($g)*> ::core::ops::Drop for $ty {
      fn drop(&mut self) {
        <Self as $crate::__private::zeroize::Zeroize>::zeroize(self);
      }
    }

    impl<$($g)*> $crate::__private::zeroize::ZeroizeOnDrop for $ty {}

    impl<$($g)*> $ty {
      /// Returns `true` when every byte is zero.
      pub fn is_null(&self) -> bool {
        use $crate::__private::subtle::ConstantTimeEq as _;
        self.as_bytes().ct_eq(&[0u8; $n]).into()
      }
    }

    impl<$($g)*> ::core::fmt::Debug for $ty {
      fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
        // `type_name` rather than `stringify!`, which cannot see the generics
        $crate::qtypestr(f, ::core::any::type_name::<Self>())?;
        f.write_str("(..)")
      }
    }

    impl<$($g)*> ::core::fmt::Display for $ty {
      fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
        ::core::fmt::Debug::fmt(self, f)
      }
    }

    impl<$($g)*> ::core::convert::AsRef<[u8]> for $ty {
      fn as_ref(&self) -> &[u8] { self.as_bytes() }
    }

    impl<$($g)*> ::core::convert::AsRef<[u8; $n]> for $ty {
      fn as_ref(&self) -> &[u8; $n] { self.as_bytes() }
    }
  };
  (for[$($generic:tt)*] $($args:tt)*) => {
    $crate::derive_sbytes!(@parse [$($generic)*] $($args)*);
  };
  ($($args:tt)*) => {
    $crate::derive_sbytes!(@parse [] $($args)*);
  };
}

/// Declares a fixed-size secret byte newtype over `[u8; N]`, the secret
/// counterpart to [`make_bytes!`](crate::make_bytes).
///
/// A `for[..]` prefix takes type parameters, held in a `PhantomData` beside
/// the bytes, for a type that utilizes parameters for tagging without mutating
/// the inner structure.
///
/// An optional trailing word follows the width. Whether the bag carries a
/// wire image, `codec` (the default) or `nocodec`.
///
/// Invokes `impl_sbytes!` and [`derive_sbytes!`](crate::derive_sbytes). A
/// newtype that needs a validating constructor or its own trait set should
/// define itself and invoke those macros manually.
#[macro_export]
macro_rules! make_sbytes {
  (@parse [$($g:tt)*] $attrs:tt $name:ident $(<$($param:ident),+>)?, $n:expr, $enc:ident) => {
    $crate::make_bytes!(@decl [$($g)*] $attrs $name $(<$($param),+>)?, $n, $enc, impl_sbytes);

    $crate::derive_sbytes!(@parse [$($g)*] $name $(<$($param),+>)?, $n);

    $crate::make_bytes!(@accessors [$($g)*] $name $(<$($param),+>)?, $n, {
      /// Copies out the inner byte array.
      pub fn to_bytes(&self) -> $crate::__private::zeroize::Zeroizing<[u8; $n]> {
        $crate::__private::zeroize::Zeroizing::new(self.inner)
      }
    });

    impl<$($g)*> $crate::__private::zeroize::Zeroize for $name $(<$($param),+>)? {
      fn zeroize(&mut self) {
        $crate::__private::zeroize::Zeroize::zeroize(&mut self.inner);
      }
    }

    impl<$($g)*> ::core::clone::Clone for $name $(<$($param),+>)? {
      fn clone(&self) -> Self {
        Self::from_bytes(self.inner)
      }
    }

    impl<$($g)*> ::core::cmp::Eq for $name $(<$($param),+>)? {}

    impl<$($g)*> ::core::cmp::PartialEq for $name $(<$($param),+>)? {
      fn eq(&self, other: &Self) -> bool {
        $crate::__private::subtle::ConstantTimeEq::ct_eq(&self.inner[..], &other.inner[..]).into()
      }
    }
  };
  (@parse [$($g:tt)*] $attrs:tt $name:ident $(<$($param:ident),+>)?, $n:expr) => {
    $crate::make_sbytes!(@parse [$($g)*] $attrs $name $(<$($param),+>)?, $n, codec);
  };
  ($(#[$attr:meta])* for[$($generic:tt)*] $name:ident<$($param:ident),+>, $($args:tt)*) => {
    $crate::make_sbytes!(@parse [$($generic)*] {$(#[$attr])*} $name<$($param),+>, $($args)*);
  };
  ($(#[$attr:meta])* $name:ident, $($args:tt)*) => {
    $crate::make_sbytes!(@parse [] {$(#[$attr])*} $name, $($args)*);
  };
}

/// The secret counterpart to [`dlgt_codec!`](crate::dlgt_codec), for an
/// operational type whose wire image is key material.
///
/// Same delegation through `$bytes`, staged through
/// [`impl_stype!`](crate::impl_stype)'s wiping pair rather than the growable
/// one, which would strand the plaintext in a heap buffer nothing wipes.
///
/// `$n` bounds the encoded width rather than fixing it: the staging buffer is
/// an [`ArrayBuf<$n>`](crate::ArrayBuf), so a narrower image is emitted as
/// written and a wider one panics on the overflowing write.
#[cfg(feature = "codec")]
#[macro_export]
macro_rules! dlgt_scodec {
  (@parse [$($impl_generics:tt)*] $ops:ty => $bytes:ty, $hash:ty, $err:ty, $n:expr) => {
    $crate::dlgt_codec!(@delegate [$($impl_generics)*] $ops => $bytes, $hash, $err);

    $crate::impl_stype!(@parse [$($impl_generics)*] $ops, $n, $err);
  };
  (for[$($generic:tt)*] $($args:tt)*) => {
    $crate::dlgt_scodec!(@parse [$($generic)*] $($args)*);
  };
  ($($args:tt)*) => {
    $crate::dlgt_scodec!(@parse [] $($args)*);
  };
}

#[cfg(all(test, feature = "codec"))]
mod tests {
  use super::{ArrDecoder, ArrEncoder, ArrayBuf, MAX_ARR_SIZE};
  use crate::codec::{DecodeError, EncodeBuf};
  use crate::prelude::*;

  use bitcoin_consensus_encoding::{Decoder, Encoder};
  use rstest::*;
  use zeroize::Zeroize;

  fn filled<const N: usize>(fill: u8, len: usize) -> ArrayBuf<N> {
    let mut b = ArrayBuf::<N>::new();
    b.extend_from_slice(&vec![fill; len]);
    b
  }

  /// Consumes the whole cursor, so `end()` sees no trailing bytes.
  fn take_all(data: &mut &[u8]) -> Result<Vec<u8>, DecodeError> {
    let out = data.to_vec();
    *data = &[];
    Ok(out)
  }

  #[rstest]
  fn arr_encoder_emits_written_prefix_only() {
    // A short write into a wide buffer must not leak the zero padding.
    let mut enc = ArrEncoder::new(filled::<64>(0xAB, 10));
    assert_eq!(enc.current_chunk(), [0xAB; 10]);
    assert!(!enc.advance());
    assert_eq!(enc.current_chunk(), &[] as &[u8]);
  }

  /// The wipe itself. `Drop` on both types delegates straight to this, and
  /// observing the freed storage directly would need `unsafe`, which the
  /// workspace denies.
  #[rstest]
  fn arrbuf_zeroize_clears_contents_and_len() {
    let mut buf = filled::<32>(0xCD, 32);
    assert_eq!(buf.as_bytes(), [0xCD; 32]);
    buf.zeroize();
    assert_eq!(buf.len(), 0);
    assert_eq!(buf.spare(), 32);
    assert_eq!(buf.as_bytes(), &[] as &[u8]);
  }

  /// The cap is a compile-time assert, so only the accepted side is testable
  /// here; `N` above the bound fails to build with "unusually large zeroized
  /// buffer" wherever the encoder or decoder is instantiated.
  #[rstest]
  fn max_width_is_accepted() {
    let enc = ArrEncoder::new(ArrayBuf::<{ MAX_ARR_SIZE }>::new());
    assert_eq!(enc.current_chunk(), &[] as &[u8]);
    let dec = ArrDecoder::<Vec<u8>, { MAX_ARR_SIZE }>::new(take_all);
    assert_eq!(dec.read_limit(), MAX_ARR_SIZE);
  }

  #[rstest]
  fn arr_decoder_roundtrips_and_bounds_reads() {
    let mut dec = ArrDecoder::<Vec<u8>, 8>::new(take_all);
    assert_eq!(dec.read_limit(), 8);
    let mut input: &[u8] = &[1, 2, 3];
    assert!(dec.push_bytes(&mut input).unwrap_or(false));
    assert!(input.is_empty());
    assert_eq!(dec.read_limit(), 5);
    assert_eq!(dec.end().unwrap_or_default(), vec![1, 2, 3]);
  }

  #[rstest]
  fn arr_decoder_stops_at_capacity() {
    let mut dec = ArrDecoder::<Vec<u8>, 4>::new(take_all);
    let mut input: &[u8] = &[9; 10];
    assert!(dec.push_bytes(&mut input).unwrap_or(false));
    assert_eq!(input.len(), 6, "excess must be left for the caller");
    assert_eq!(dec.read_limit(), 0);
    assert!(!dec.push_bytes(&mut input).unwrap_or(true));
  }

  /// Both encoders redact: a `{:?}` in a panic must not print key material.
  #[rstest]
  fn debug_impls_redact_contents() {
    let enc = ArrEncoder::new(filled::<8>(0xFF, 8));
    let dbg = format!("{enc:?}");
    assert!(!dbg.contains("255") && !dbg.contains("ff"), "{dbg}");
    assert!(dbg.contains("len: 8"));

    let adec = ArrDecoder::<Vec<u8>, 16>::new(take_all);
    assert!(format!("{adec:?}").contains("limit: 16"));
  }
}
