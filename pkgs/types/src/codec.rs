//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Codec traits and helpers.

use crate::prelude::*;

use core::convert::Infallible;
use core::fmt::{Debug, Display, Formatter, Result as FmtResult};

/// Maximum bytes to pre-allocate per batch when deserializing vectors.
const MAX_VECTOR_ALLOCATE: usize = 5_000_000;

/// An error encountered during consensus decoding.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum DecodeError<E = Infallible> {
  /// A decoded field has an invalid byte length.
  BadLen {
    /// Acceptable lengths.
    expected: Vec<usize>,
    /// The length that was decoded.
    actual: usize,
  },
  /// Decode validation error.
  DecError(E),
  /// CompactSize value exceeds the allowed limit.
  CompactSizeExceedsLimit {
    /// The configured limit.
    limit: usize,
    /// The decoded value.
    value: u64,
  },
  /// Not enough bytes remaining in the cursor.
  Eof {
    /// Bytes needed for the read.
    needed: usize,
    /// Bytes actually remaining.
    remaining: usize,
  },
  /// Decoded bytes are not valid UTF-8.
  InvalidUtf8,
  /// A decoded value does not match any expected value.
  InvalidValue {
    /// Acceptable values.
    expected: Vec<u64>,
    /// The value that was decoded.
    actual: u64,
  },
  /// CompactSize encoding is not minimal.
  NonMinimalCompactSize {
    /// The decoded value that was not minimally encoded.
    value: u64,
  },
  /// Unconsumed bytes remain after decoding.
  TrailingBytes {
    /// Number of bytes left over.
    remaining: usize,
  },
}

impl<E: Display> Display for DecodeError<E> {
  fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
    match self {
      Self::BadLen { expected, actual } => {
        write!(f, "invalid length: expected one of {expected:?}, got {actual}")
      }
      Self::DecError(e) => write!(f, "decode validation: {e}"),
      Self::CompactSizeExceedsLimit { limit, value } => {
        write!(f, "compact size value {value} exceeds limit {limit}",)
      }
      Self::Eof { needed, remaining } => {
        write!(f, "unexpected eof: needed {needed} bytes, {remaining} remaining",)
      }
      Self::InvalidUtf8 => write!(f, "invalid utf-8 in string"),
      Self::InvalidValue { expected, actual } => {
        write!(f, "invalid value: expected one of {expected:?}, got {actual}")
      }
      Self::NonMinimalCompactSize { value } => {
        write!(f, "non-minimal compact size encoding for value {value}",)
      }
      Self::TrailingBytes { remaining } => {
        write!(f, "{remaining} trailing bytes after decode")
      }
    }
  }
}

impl DecodeError {
  /// Convert a `DecodeError<Infallible>` into `DecodeError<F>`.
  pub fn lift<F>(self) -> DecodeError<F> {
    match self {
      Self::BadLen { expected, actual } => DecodeError::BadLen { expected, actual },
      Self::CompactSizeExceedsLimit { limit, value } => DecodeError::CompactSizeExceedsLimit { limit, value },
      Self::DecError(inf) => match inf {},
      Self::Eof { needed, remaining } => DecodeError::Eof { needed, remaining },
      Self::InvalidUtf8 => DecodeError::InvalidUtf8,
      Self::InvalidValue { expected, actual } => DecodeError::InvalidValue { expected, actual },
      Self::NonMinimalCompactSize { value } => DecodeError::NonMinimalCompactSize { value },
      Self::TrailingBytes { remaining } => DecodeError::TrailingBytes { remaining },
    }
  }
}

#[cfg(feature = "std")]
impl<E: Debug + Display> std::error::Error for DecodeError<E> {}

/// Checks that `data` has at least `n` bytes remaining.
///
/// # Errors
///
/// Returns `DecodeError::Eof` if the slice is too short.
pub fn ensure(data: &[u8], n: usize) -> Result<(), DecodeError> {
  if data.len() < n {
    Err(DecodeError::Eof {
      needed: n,
      remaining: data.len(),
    })
  } else {
    Ok(())
  }
}

/// Reads exactly `N` bytes from the cursor, advancing it.
///
/// # Errors
///
/// Returns `DecodeError::Eof` when fewer than `N` bytes remain.
pub fn take<const N: usize>(data: &mut &[u8]) -> Result<[u8; N], DecodeError> {
  ensure(data, N)?;
  let mut arr = [0u8; N];
  arr.copy_from_slice(&data[..N]);
  *data = &data[N..];
  Ok(arr)
}

/// Reads a big-endian `u16` (used for network ports).
pub fn read_u16_be(data: &mut &[u8]) -> Result<u16, DecodeError> {
  take::<2>(data).map(u16::from_be_bytes)
}

/// Reads exactly `n` bytes as a sub-slice (zero-copy).
pub fn read_bytes<'a>(data: &mut &'a [u8], n: usize) -> Result<&'a [u8], DecodeError> {
  ensure(data, n)?;
  let (head, rest) = data.split_at(n);
  *data = rest;
  Ok(head)
}

/// Reads a CompactSize-encoded `u64` with minimal encoding check.
pub fn read_compact_u64(data: &mut &[u8]) -> Result<u64, DecodeError> {
  let first = u8::decode(data)?;
  match first {
    0..=0xFC => Ok(u64::from(first)),
    0xFD => {
      let v = u16::decode(data)?;
      if v < 0xFD {
        return Err(DecodeError::NonMinimalCompactSize { value: u64::from(v) });
      }
      Ok(u64::from(v))
    }
    0xFE => {
      let v = u32::decode(data)?;
      if v < 0x10000 {
        return Err(DecodeError::NonMinimalCompactSize { value: u64::from(v) });
      }
      Ok(u64::from(v))
    }
    0xFF => {
      let v = u64::decode(data)?;
      if v < 0x1_0000_0000 {
        return Err(DecodeError::NonMinimalCompactSize { value: v });
      }
      Ok(v)
    }
  }
}

/// Reads a CompactSize-encoded length with a limit.
pub fn read_compact_size(data: &mut &[u8], limit: usize) -> Result<usize, DecodeError> {
  let value = read_compact_u64(data)?;
  let n = usize::try_from(value).map_err(|_| DecodeError::CompactSizeExceedsLimit { limit, value })?;
  if n > limit {
    return Err(DecodeError::CompactSizeExceedsLimit { limit, value });
  }
  Ok(n)
}

/// Append-only byte buffer used by [`BaseCodec::encode`].
pub trait EncodeBuf {
  /// Appends a single byte.
  fn push(&mut self, byte: u8);

  /// Appends a byte slice.
  fn extend_from_slice(&mut self, data: &[u8]);
}

impl EncodeBuf for Vec<u8> {
  fn push(&mut self, byte: u8) {
    self.push(byte);
  }

  fn extend_from_slice(&mut self, data: &[u8]) {
    self.extend_from_slice(data);
  }
}

/// Fixed-size encode buffer backed by `[u8; N]`.
///
/// # Panics
///
/// Writing more than `N` bytes (via the [`EncodeBuf`] impl) panics with an
/// index-out-of-bounds.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct ArrayBuf<const N: usize> {
  buf: [u8; N],
  len: usize,
}

impl<const N: usize> ArrayBuf<N> {
  /// Creates an empty buffer.
  pub const fn new() -> Self {
    Self { buf: [0u8; N], len: 0 }
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

impl<const N: usize> Default for ArrayBuf<N> {
  fn default() -> Self {
    Self::new()
  }
}

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

/// Encodes a `usize` as a CompactSize integer.
pub fn write_compact_size(value: usize, buf: &mut impl EncodeBuf) {
  write_compact_u64(value as u64, buf);
}

/// Encodes a `u64` as a CompactSize integer.
pub fn write_compact_u64(value: u64, buf: &mut impl EncodeBuf) {
  match value {
    0..=0xFC => buf.push(value as u8),
    0xFD..=0xFFFF => {
      buf.push(0xFD);
      buf.extend_from_slice(&(value as u16).to_le_bytes());
    }
    0x1_0000..=0xFFFF_FFFF => {
      buf.push(0xFE);
      buf.extend_from_slice(&(value as u32).to_le_bytes());
    }
    _ => {
      buf.push(0xFF);
      buf.extend_from_slice(&value.to_le_bytes());
    }
  }
}

/// Links a type to its underlying base integer type.
pub trait NumCodec<N>: Sized {
  /// Constructs from the base integer.
  fn from_base(v: N) -> Self;

  /// Returns the base integer.
  fn to_base(&self) -> N;
}

/// Stable per-type identifier derived from the type name.
pub trait TypeId {
  const TYPE_ID: u32;
}

/// Cursor-based encode/decode for consensus wire types.
pub trait BaseCodec<E = Infallible>: Sized {
  /// Decodes from the cursor, advancing it past consumed bytes.
  ///
  /// # Errors
  ///
  /// Returns `DecodeError` on malformed input.
  fn decode(data: &mut &[u8]) -> Result<Self, DecodeError<E>>;

  /// Encodes into the buffer.
  fn encode(&self, buf: &mut impl EncodeBuf);
}

impl BaseCodec for u8 {
  fn decode(data: &mut &[u8]) -> Result<Self, DecodeError> {
    Ok(take::<1>(data)?[0])
  }

  fn encode(&self, buf: &mut impl EncodeBuf) {
    buf.push(*self);
  }
}

impl BaseCodec for i8 {
  fn decode(data: &mut &[u8]) -> Result<Self, DecodeError> {
    Ok(take::<1>(data)?[0] as i8)
  }

  fn encode(&self, buf: &mut impl EncodeBuf) {
    buf.push(*self as u8);
  }
}

impl BaseCodec for u16 {
  fn decode(data: &mut &[u8]) -> Result<Self, DecodeError> {
    take::<2>(data).map(Self::from_le_bytes)
  }

  fn encode(&self, buf: &mut impl EncodeBuf) {
    buf.extend_from_slice(&self.to_le_bytes());
  }
}

impl BaseCodec for i16 {
  fn decode(data: &mut &[u8]) -> Result<Self, DecodeError> {
    take::<2>(data).map(Self::from_le_bytes)
  }

  fn encode(&self, buf: &mut impl EncodeBuf) {
    buf.extend_from_slice(&self.to_le_bytes());
  }
}

impl BaseCodec for u32 {
  fn decode(data: &mut &[u8]) -> Result<Self, DecodeError> {
    take::<4>(data).map(Self::from_le_bytes)
  }

  fn encode(&self, buf: &mut impl EncodeBuf) {
    buf.extend_from_slice(&self.to_le_bytes());
  }
}

impl BaseCodec for i32 {
  fn decode(data: &mut &[u8]) -> Result<Self, DecodeError> {
    take::<4>(data).map(Self::from_le_bytes)
  }

  fn encode(&self, buf: &mut impl EncodeBuf) {
    buf.extend_from_slice(&self.to_le_bytes());
  }
}

impl BaseCodec for u64 {
  fn decode(data: &mut &[u8]) -> Result<Self, DecodeError> {
    take::<8>(data).map(Self::from_le_bytes)
  }

  fn encode(&self, buf: &mut impl EncodeBuf) {
    buf.extend_from_slice(&self.to_le_bytes());
  }
}

impl BaseCodec for i64 {
  fn decode(data: &mut &[u8]) -> Result<Self, DecodeError> {
    take::<8>(data).map(Self::from_le_bytes)
  }

  fn encode(&self, buf: &mut impl EncodeBuf) {
    buf.extend_from_slice(&self.to_le_bytes());
  }
}

impl BaseCodec for bool {
  fn decode(data: &mut &[u8]) -> Result<Self, DecodeError> {
    let byte = take::<1>(data)?[0];
    match byte {
      0 => Ok(false),
      1 => Ok(true),
      _ => Err(DecodeError::InvalidValue {
        expected: vec![0, 1],
        actual: u64::from(byte),
      }),
    }
  }

  fn encode(&self, buf: &mut impl EncodeBuf) {
    buf.push(u8::from(*self));
  }
}

impl<const N: usize> BaseCodec for [u8; N] {
  fn decode(data: &mut &[u8]) -> Result<Self, DecodeError> {
    take::<N>(data)
  }

  fn encode(&self, buf: &mut impl EncodeBuf) {
    buf.extend_from_slice(self);
  }
}

impl<T: BaseCodec> BaseCodec for Vec<T> {
  fn decode(data: &mut &[u8]) -> Result<Self, DecodeError> {
    let count = read_compact_size(data, data.len())?;
    let batch = MAX_VECTOR_ALLOCATE / core::mem::size_of::<T>().max(1);
    let mut items = Vec::new();
    let mut allocated = 0usize;
    for _ in 0..count {
      if items.len() == allocated {
        allocated = count.min(allocated + batch);
        items.reserve(allocated - items.len());
      }
      items.push(T::decode(data)?);
    }
    Ok(items)
  }

  fn encode(&self, buf: &mut impl EncodeBuf) {
    write_compact_size(self.len(), buf);
    for item in self {
      item.encode(buf);
    }
  }
}

impl BaseCodec for String {
  fn decode(data: &mut &[u8]) -> Result<Self, DecodeError> {
    let bytes = Vec::<u8>::decode(data)?;
    Self::from_utf8(bytes).map_err(|_| DecodeError::InvalidUtf8)
  }

  fn encode(&self, buf: &mut impl EncodeBuf) {
    write_compact_size(self.len(), buf);
    buf.extend_from_slice(self.as_bytes());
  }
}

/// Consensus types that have internal consistency checks.
pub trait Checkable {
  /// The error type returned on failure.
  type Error;

  /// Checks structural invariants, returning the first violation.
  #[must_use]
  fn check(&self) -> Option<Self::Error>;
}

/// Canonical hashed representation.
pub trait Hashable {
  /// The hash output type.
  type Hash;

  /// Computes the canonical hash of this value.
  fn hash(&self) -> Self::Hash;
}

/// Marker trait for codec coverage enforcement.
///
/// Implemented automatically for all `Codec` types via blanket impl, and
/// manually via `#[derive(Unencodable)]` for non-wire types.
#[doc(hidden)]
pub trait __CodecMarker {}

/// Guard trait preventing `Unencodable` on wire types.
///
/// Both `#[derive(Unencodable)]` and the blanket over `BaseCodec` implement
/// this trait; any type carrying both triggers a compiler error.
#[doc(hidden)]
pub trait __UnencodableMarker {}

impl<T: BaseCodec> __UnencodableMarker for T {}

cfg_if::cfg_if! {
  if #[cfg(feature = "serde")] {
    use serde::{Serialize, de::DeserializeOwned};

    pub trait Codec<E = Infallible>: BaseCodec<E> + Hashable + TypeId + Serialize + DeserializeOwned {}

    impl<T: BaseCodec<E> + Hashable + TypeId + Serialize + DeserializeOwned, E> Codec<E> for T {}
  } else {
    pub trait Codec<E = Infallible>: BaseCodec<E> + Hashable + TypeId {}

    impl<T: BaseCodec<E> + Hashable + TypeId, E> Codec<E> for T {}
  }
}

impl<T: Codec> __CodecMarker for T {}
