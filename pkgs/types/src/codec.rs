//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Codec traits and helpers for cursor-based encoding and decoding.

use crate::prelude::*;

use core::fmt;

/// An error encountered during consensus decoding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodeError {
  /// Not enough bytes remaining in the cursor.
  Eof {
    /// Bytes needed for the read.
    needed: usize,
    /// Bytes actually remaining.
    remaining: usize,
  },
  /// CompactSize encoding is not minimal.
  NonMinimalCompactSize {
    /// The decoded value that was not minimally encoded.
    value: u64,
  },
  /// CompactSize value exceeds the allowed limit.
  CompactSizeExceedsLimit {
    /// The configured limit.
    limit: usize,
    /// The decoded value.
    value: u64,
  },
}

impl fmt::Display for DecodeError {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    match self {
      Self::Eof { needed, remaining } => {
        write!(f, "unexpected eof: needed {needed} bytes, {remaining} remaining",)
      }
      Self::NonMinimalCompactSize { value } => {
        write!(f, "non-minimal compact size encoding for value {value}",)
      }
      Self::CompactSizeExceedsLimit { limit, value } => {
        write!(f, "compact size value {value} exceeds limit {limit}",)
      }
    }
  }
}

#[cfg(feature = "std")]
impl std::error::Error for DecodeError {}

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

/// Reads a single byte.
pub fn read_u8(data: &mut &[u8]) -> Result<u8, DecodeError> {
  Ok(take::<1>(data)?[0])
}

/// Reads a single byte as a bool (0 = false, nonzero = true).
pub fn read_bool(data: &mut &[u8]) -> Result<bool, DecodeError> {
  read_u8(data).map(|b| b != 0)
}

/// Reads a little-endian `u16`.
pub fn read_u16_le(data: &mut &[u8]) -> Result<u16, DecodeError> {
  take::<2>(data).map(u16::from_le_bytes)
}

/// Reads a big-endian `u16` (used for network ports).
pub fn read_u16_be(data: &mut &[u8]) -> Result<u16, DecodeError> {
  take::<2>(data).map(u16::from_be_bytes)
}

/// Reads a little-endian `u32`.
pub fn read_u32_le(data: &mut &[u8]) -> Result<u32, DecodeError> {
  take::<4>(data).map(u32::from_le_bytes)
}

/// Reads a little-endian `u64`.
pub fn read_u64_le(data: &mut &[u8]) -> Result<u64, DecodeError> {
  take::<8>(data).map(u64::from_le_bytes)
}

/// Reads a little-endian `i16`.
pub fn read_i16_le(data: &mut &[u8]) -> Result<i16, DecodeError> {
  take::<2>(data).map(i16::from_le_bytes)
}

/// Reads a little-endian `i32`.
pub fn read_i32_le(data: &mut &[u8]) -> Result<i32, DecodeError> {
  take::<4>(data).map(i32::from_le_bytes)
}

/// Reads a little-endian `i64`.
pub fn read_i64_le(data: &mut &[u8]) -> Result<i64, DecodeError> {
  take::<8>(data).map(i64::from_le_bytes)
}

/// Reads exactly `n` bytes as a sub-slice (zero-copy).
pub fn read_bytes<'a>(data: &mut &'a [u8], n: usize) -> Result<&'a [u8], DecodeError> {
  ensure(data, n)?;
  let (head, rest) = data.split_at(n);
  *data = rest;
  Ok(head)
}

/// Reads a fixed-size byte newtype via `From<[u8; N]>`.
pub fn read_type<T, const N: usize>(data: &mut &[u8]) -> Result<T, DecodeError>
where
  T: From<[u8; N]>,
{
  take::<N>(data).map(T::from)
}

/// Reads a CompactSize-prefixed byte blob.
///
/// # Errors
///
/// Returns `DecodeError` when the prefix or payload is
/// malformed or exceeds `limit`.
pub fn read_blob(data: &mut &[u8], limit: usize) -> Result<Vec<u8>, DecodeError> {
  let len = read_compact_size(data, limit)?;
  Ok(read_bytes(data, len)?.to_vec())
}

/// Writes a CompactSize-prefixed byte blob.
pub fn write_blob(bytes: &[u8], buf: &mut Vec<u8>) {
  write_compact_size(bytes.len(), buf);
  buf.extend_from_slice(bytes);
}

/// Reads a CompactSize-encoded `u64` with minimal encoding check.
pub fn read_compact_u64(data: &mut &[u8]) -> Result<u64, DecodeError> {
  let first = read_u8(data)?;
  match first {
    0..=0xFC => Ok(u64::from(first)),
    0xFD => {
      let v = read_u16_le(data)?;
      if v < 0xFD {
        return Err(DecodeError::NonMinimalCompactSize { value: u64::from(v) });
      }
      Ok(u64::from(v))
    }
    0xFE => {
      let v = read_u32_le(data)?;
      if v < 0x10000 {
        return Err(DecodeError::NonMinimalCompactSize { value: u64::from(v) });
      }
      Ok(u64::from(v))
    }
    0xFF => {
      let v = read_u64_le(data)?;
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

/// Encodes a `usize` as a CompactSize integer.
pub fn write_compact_size(value: usize, buf: &mut Vec<u8>) {
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
      buf.extend_from_slice(&(value as u64).to_le_bytes());
    }
  }
}

/// Reads a CompactSize-prefixed vector of `Codec` elements.
///
/// # Errors
///
/// Returns `DecodeError` when the prefix, element count,
/// or any element is malformed.
pub fn read_vec<T: Codec>(data: &mut &[u8], limit: usize) -> Result<Vec<T>, DecodeError> {
  let count = read_compact_size(data, limit)?;
  let mut items = Vec::with_capacity(count);
  for _ in 0..count {
    items.push(T::decode(data)?);
  }
  Ok(items)
}

/// Writes a CompactSize-prefixed vector of `Codec` elements.
pub fn write_vec<T: Codec>(items: &[T], buf: &mut Vec<u8>) {
  write_compact_size(items.len(), buf);
  for item in items {
    item.encode(buf);
  }
}

/// Links a type to its underlying base integer type.
pub trait NumCodec<N>: Sized {
  /// Constructs from the base integer.
  fn from_base(v: N) -> Self;

  /// Returns the base integer.
  fn to_base(&self) -> N;
}

/// Cursor-based encode/decode for consensus wire types.
pub trait Codec: Sized {
  /// Decodes from the cursor, advancing it past consumed bytes.
  ///
  /// # Errors
  ///
  /// Returns `DecodeError` on malformed input.
  fn decode(data: &mut &[u8]) -> Result<Self, DecodeError>;

  /// Encodes into the buffer.
  fn encode(&self, buf: &mut Vec<u8>);
}

impl Codec for u8 {
  fn decode(data: &mut &[u8]) -> Result<Self, DecodeError> {
    read_u8(data)
  }

  fn encode(&self, buf: &mut Vec<u8>) {
    buf.push(*self);
  }
}

impl Codec for i8 {
  fn decode(data: &mut &[u8]) -> Result<Self, DecodeError> {
    read_u8(data).map(|b| b as i8)
  }

  fn encode(&self, buf: &mut Vec<u8>) {
    buf.push(*self as u8);
  }
}

impl Codec for u16 {
  fn decode(data: &mut &[u8]) -> Result<Self, DecodeError> {
    read_u16_le(data)
  }

  fn encode(&self, buf: &mut Vec<u8>) {
    buf.extend_from_slice(&self.to_le_bytes());
  }
}

impl Codec for i16 {
  fn decode(data: &mut &[u8]) -> Result<Self, DecodeError> {
    read_i16_le(data)
  }

  fn encode(&self, buf: &mut Vec<u8>) {
    buf.extend_from_slice(&self.to_le_bytes());
  }
}

impl Codec for u32 {
  fn decode(data: &mut &[u8]) -> Result<Self, DecodeError> {
    read_u32_le(data)
  }

  fn encode(&self, buf: &mut Vec<u8>) {
    buf.extend_from_slice(&self.to_le_bytes());
  }
}

impl Codec for i32 {
  fn decode(data: &mut &[u8]) -> Result<Self, DecodeError> {
    read_i32_le(data)
  }

  fn encode(&self, buf: &mut Vec<u8>) {
    buf.extend_from_slice(&self.to_le_bytes());
  }
}

impl Codec for u64 {
  fn decode(data: &mut &[u8]) -> Result<Self, DecodeError> {
    read_u64_le(data)
  }

  fn encode(&self, buf: &mut Vec<u8>) {
    buf.extend_from_slice(&self.to_le_bytes());
  }
}

impl Codec for i64 {
  fn decode(data: &mut &[u8]) -> Result<Self, DecodeError> {
    read_i64_le(data)
  }

  fn encode(&self, buf: &mut Vec<u8>) {
    buf.extend_from_slice(&self.to_le_bytes());
  }
}

impl Codec for bool {
  fn decode(data: &mut &[u8]) -> Result<Self, DecodeError> {
    read_bool(data)
  }

  fn encode(&self, buf: &mut Vec<u8>) {
    buf.push(u8::from(*self));
  }
}
