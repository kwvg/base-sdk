//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Codec traits and helpers.

use crate::prelude::*;
use crate::type_id::TypeId;
use crate::{CompactSize, Hashable};

use core::convert::Infallible;
use core::fmt;

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

impl<E: fmt::Display> fmt::Display for DecodeError<E> {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
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

#[cfg(feature = "std")]
impl<E: std::error::Error + 'static> std::error::Error for DecodeError<E> {
  fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
    match self {
      Self::DecError(e) => Some(e),
      _ => None,
    }
  }
}

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

/// Reads a CompactSize-prefixed byte string of at most `limit` bytes as a
/// sub-slice (zero-copy).
///
/// # Errors
///
/// Returns [`DecodeError::CompactSizeExceedsLimit`] when the length exceeds
/// [`MAX_SIZE`](crate::MAX_SIZE) or `limit`, [`DecodeError::Eof`] when it
/// exceeds the bytes left after the prefix, and any error of
/// [`BaseCodec::decode`].
pub fn read_bytes_limited<'a>(data: &mut &'a [u8], limit: usize) -> Result<&'a [u8], DecodeError> {
  let len = decode_count(data, limit)?;
  read_bytes(data, len)
}

/// Reads a CompactSize-prefixed vector of at most `limit` elements. The count
/// is checked before any element is decoded or allocated.
///
/// # Errors
///
/// Returns [`DecodeError::CompactSizeExceedsLimit`] when the count exceeds
/// [`MAX_SIZE`](crate::MAX_SIZE) or `limit`, [`DecodeError::Eof`] when it
/// exceeds the bytes left after the prefix, and any error of
/// [`BaseCodec::decode`] for `T`.
pub fn decode_vec_limited<T: BaseCodec>(data: &mut &[u8], limit: usize) -> Result<Vec<T>, DecodeError> {
  let count = decode_count(data, limit)?;
  decode_elements(data, count)
}

/// Reads a count prefix bounded by `limit`, by `MAX_SIZE` and by the input.
fn decode_count(data: &mut &[u8], limit: usize) -> Result<usize, DecodeError> {
  let count = CompactSize::decode_checked(data)?.into_len(limit)?;
  ensure(data, count)?;
  Ok(count)
}

/// Decodes `count` elements, allocating in batches so that a count the input
/// cannot back costs at most one batch.
fn decode_elements<T: BaseCodec>(data: &mut &[u8], count: usize) -> Result<Vec<T>, DecodeError> {
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

/// The widest wire image a type's buffering decoder will accept.
pub trait SerBound {
  /// Upper bound on the encoded width, in bytes.
  const MAX_SER_SIZE: usize;
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

/// A non-zero byte other than `1` re-encodes as `1`, so such input does not
/// round-trip.
impl BaseCodec for bool {
  fn decode(data: &mut &[u8]) -> Result<Self, DecodeError> {
    Ok(take::<1>(data)?[0] != 0)
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
    let count = CompactSize::decode_len(data)?;
    decode_elements(data, count)
  }

  fn encode(&self, buf: &mut impl EncodeBuf) {
    CompactSize::from(self.len()).encode(buf);
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
    CompactSize::from(self.len()).encode(buf);
    buf.extend_from_slice(self.as_bytes());
  }
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

    #[doc(hidden)]
    pub trait Codec<E = Infallible>: BaseCodec<E> + Hashable + TypeId + Serialize + DeserializeOwned {}

    impl<T: BaseCodec<E> + Hashable + TypeId + Serialize + DeserializeOwned, E> Codec<E> for T {}
  } else {
    #[doc(hidden)]
    pub trait Codec<E = Infallible>: BaseCodec<E> + Hashable + TypeId {}

    impl<T: BaseCodec<E> + Hashable + TypeId, E> Codec<E> for T {}
  }
}

impl<T: Codec> __CodecMarker for T {}

#[cfg(test)]
mod tests {
  use super::{decode_vec_limited, read_bytes_limited, BaseCodec, DecodeError};
  use crate::prelude::*;
  use crate::{VecDecoder, VecEncoder, MAX_SIZE};

  use rstest::*;

  use core::fmt;

  #[derive(Clone, Debug, Eq, PartialEq)]
  struct SampleError;

  impl fmt::Display for SampleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
      write!(f, "sample text")
    }
  }

  #[rstest]
  fn dec_error_displays_the_inner_error() {
    let err: DecodeError<SampleError> = DecodeError::DecError(SampleError);
    assert_eq!(err.to_string(), "decode validation: sample text");
  }

  #[rstest]
  fn expected_sets_are_rendered_in_full() {
    let err = DecodeError::<SampleError>::BadLen {
      expected: vec![33, 65],
      actual: 12,
    };
    assert_eq!(err.to_string(), "invalid length: expected one of [33, 65], got 12");
  }

  #[rstest]
  #[case::bad_len(DecodeError::BadLen { expected: vec![33, 65], actual: 12 })]
  #[case::exceeds_limit(DecodeError::CompactSizeExceedsLimit { limit: 8, value: 9 })]
  #[case::eof(DecodeError::Eof { needed: 4, remaining: 1 })]
  #[case::invalid_utf8(DecodeError::InvalidUtf8)]
  #[case::invalid_value(DecodeError::InvalidValue { expected: vec![0, 1], actual: 7 })]
  #[case::non_minimal(DecodeError::NonMinimalCompactSize { value: 1 })]
  #[case::trailing(DecodeError::TrailingBytes { remaining: 3 })]
  fn lift_preserves_variant_and_message(#[case] err: DecodeError) {
    let before = err.to_string();
    let lifted: DecodeError<SampleError> = err.lift();
    assert_eq!(lifted.to_string(), before);
    assert!(!matches!(lifted, DecodeError::DecError(_)));
  }

  #[rstest]
  #[case::zero(0x00, false)]
  #[case::one(0x01, true)]
  #[case::two(0x02, true)]
  #[case::high(0x80, true)]
  #[case::max(0xFF, true)]
  fn bool_decodes_any_non_zero_byte_as_true(#[case] byte: u8, #[case] value: bool) {
    let mut cursor: &[u8] = &[byte];
    assert_eq!(bool::decode(&mut cursor), Ok(value));
    assert!(cursor.is_empty());
  }

  #[rstest]
  #[case::false_(false, 0x00)]
  #[case::true_(true, 0x01)]
  fn bool_encodes_as_zero_or_one(#[case] value: bool, #[case] byte: u8) {
    let mut buf = Vec::new();
    value.encode(&mut buf);
    assert_eq!(buf, [byte]);
  }

  #[rstest]
  fn vec_count_past_the_input_is_eof() {
    let wire: &[u8] = &[0x03, 0xAA, 0xBB];
    assert_eq!(
      Vec::<u8>::decode(&mut &*wire),
      Err(DecodeError::Eof {
        needed: 3,
        remaining: 2
      })
    );
    assert_eq!(
      String::decode(&mut &*wire),
      Err(DecodeError::Eof {
        needed: 3,
        remaining: 2
      })
    );
  }

  fn exceeds(limit: usize, value: u64) -> DecodeError {
    DecodeError::CompactSizeExceedsLimit { limit, value }
  }

  #[rstest]
  #[case::empty(&[0x00], 2, Ok(vec![]))]
  #[case::below(&[0x01, 0x0A, 0x00], 2, Ok(vec![10]))]
  #[case::at_limit(&[0x02, 0x0A, 0x00, 0x0B, 0x00], 2, Ok(vec![10, 11]))]
  #[case::past_limit(&[0x03, 0x0A, 0x00, 0x0B, 0x00, 0x0C, 0x00], 2, Err(exceeds(2, 3)))]
  #[case::past_limit_and_input(&[0xFD, 0xFF, 0xFF], 2, Err(exceeds(2, 0xFFFF)))]
  #[case::past_max_size(&[0xFE, 0x01, 0x00, 0x00, 0x02], usize::MAX, Err(exceeds(MAX_SIZE as usize, MAX_SIZE + 1)))]
  #[case::past_input(&[0x03, 0x0A, 0x00], 3, Err(DecodeError::Eof { needed: 3, remaining: 2 }))]
  #[case::short_element(&[0x02, 0x0A, 0x00, 0x0B], 2, Err(DecodeError::Eof { needed: 2, remaining: 1 }))]
  fn decode_vec_limited_bounds_the_count(
    #[case] wire: &[u8],
    #[case] limit: usize,
    #[case] expected: Result<Vec<u16>, DecodeError>,
  ) {
    assert_eq!(decode_vec_limited::<u16>(&mut &*wire, limit), expected);
  }

  #[rstest]
  #[case::empty(&[0x00], 2, Ok(&[][..]))]
  #[case::at_limit(&[0x02, 0xAA, 0xBB], 2, Ok(&[0xAA, 0xBB][..]))]
  #[case::past_limit(&[0x03, 0xAA, 0xBB, 0xCC], 2, Err(exceeds(2, 3)))]
  #[case::past_limit_and_input(&[0xFD, 0xFF, 0xFF], 2, Err(exceeds(2, 0xFFFF)))]
  #[case::past_max_size(&[0xFE, 0x01, 0x00, 0x00, 0x02], usize::MAX, Err(exceeds(MAX_SIZE as usize, MAX_SIZE + 1)))]
  #[case::past_input(&[0x02, 0xAA], 2, Err(DecodeError::Eof { needed: 2, remaining: 1 }))]
  fn read_bytes_limited_bounds_the_length(
    #[case] wire: &[u8],
    #[case] limit: usize,
    #[case] expected: Result<&[u8], DecodeError>,
  ) {
    assert_eq!(read_bytes_limited(&mut &*wire, limit), expected);
  }

  #[rstest]
  fn limited_reads_stop_after_the_value() {
    let wire: &[u8] = &[0x01, 0xAA, 0xFF];
    let mut cursor = wire;
    assert_eq!(read_bytes_limited(&mut cursor, 1), Ok(&[0xAA][..]));
    assert_eq!(cursor, [0xFF]);
    let mut cursor = wire;
    assert_eq!(decode_vec_limited::<u8>(&mut cursor, 1), Ok(vec![0xAA]));
    assert_eq!(cursor, [0xFF]);
  }

  #[rstest]
  fn bool_rejects_empty_input() {
    assert!(matches!(bool::decode(&mut &[][..]), Err(DecodeError::Eof { .. })));
  }

  /// Consumes the whole cursor, so `end()` sees no trailing bytes.
  fn take_all(data: &mut &[u8]) -> Result<Vec<u8>, DecodeError> {
    let out = data.to_vec();
    *data = &[];
    Ok(out)
  }

  /// Both encoders redact: a `{:?}` in a panic must not print key material.
  #[rstest]
  fn debug_impls_redact_contents() {
    let venc = VecEncoder::new(vec![0xFFu8; 8]);
    assert!(!format!("{venc:?}").contains("255"));

    let vdec = VecDecoder::<Vec<u8>>::new(take_all, 16);
    assert!(format!("{vdec:?}").contains("limit: 16"));
  }
}
