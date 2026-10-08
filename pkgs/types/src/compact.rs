//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! CompactSize-encoded integers.

use crate::codec::{BaseCodec, DecodeError, EncodeBuf};
use crate::Numeric;

/// The largest byte length or element count a range-checked CompactSize read
/// accepts.
pub const MAX_SIZE: u64 = 0x0200_0000;

/// An unsigned integer type that a type-bounded CompactSize read produces.
pub trait CompactUint: private::Sealed + Sized {
  /// The largest value of the type.
  const MAX: u64;

  /// Narrows a decoded value to the type.
  fn from_u64(value: u64) -> Option<Self>;
}

mod private {
  pub trait Sealed {}
}

macro_rules! impl_compact_uint {
  ($($ty:ty),+) => {$(
    impl private::Sealed for $ty {}

    impl CompactUint for $ty {
      const MAX: u64 = <$ty>::MAX as u64;

      fn from_u64(value: u64) -> Option<Self> {
        Self::try_from(value).ok()
      }
    }
  )+};
}

impl_compact_uint!(u8, u16, u32, u64);

/// An unsigned integer encoded in variable-width CompactSize.
#[repr(transparent)]
#[cfg_attr(feature = "serde", derive(::serde::Deserialize, ::serde::Serialize))]
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CompactSize(u64);

/// The base is the wrapped integer and the byte image is the integer itself.
impl Numeric for CompactSize {
  type Base = u64;

  type Bytes = [u8; 8];

  const ZERO: Self = Self(0);

  fn from_base(v: u64) -> Self {
    Self(v)
  }

  fn to_base(&self) -> u64 {
    self.0
  }

  fn from_lendian(bytes: [u8; 8]) -> Self {
    Self(u64::from_le_bytes(bytes))
  }

  fn to_lendian(&self) -> [u8; 8] {
    self.0.to_le_bytes()
  }

  fn from_bendian(bytes: [u8; 8]) -> Self {
    Self(u64::from_be_bytes(bytes))
  }

  fn to_bendian(&self) -> [u8; 8] {
    self.0.to_be_bytes()
  }
}

impl BaseCodec for CompactSize {
  fn decode(data: &mut &[u8]) -> Result<Self, DecodeError> {
    let first = u8::decode(data)?;
    let value = match first {
      0..=0xFC => u64::from(first),
      0xFD => {
        let value = u16::decode(data)?;
        if value < 0xFD {
          return Err(DecodeError::NonMinimalCompactSize {
            value: u64::from(value),
          });
        }
        u64::from(value)
      }
      0xFE => {
        let value = u32::decode(data)?;
        if value < 0x1_0000 {
          return Err(DecodeError::NonMinimalCompactSize {
            value: u64::from(value),
          });
        }
        u64::from(value)
      }
      0xFF => {
        let value = u64::decode(data)?;
        if value < 0x1_0000_0000 {
          return Err(DecodeError::NonMinimalCompactSize { value });
        }
        value
      }
    };
    Ok(Self(value))
  }

  fn encode(&self, buf: &mut impl EncodeBuf) {
    match self.0 {
      0..=0xFC => buf.push(self.0 as u8),
      0xFD..=0xFFFF => {
        buf.push(0xFD);
        buf.extend_from_slice(&(self.0 as u16).to_le_bytes());
      }
      0x1_0000..=0xFFFF_FFFF => {
        buf.push(0xFE);
        buf.extend_from_slice(&(self.0 as u32).to_le_bytes());
      }
      _ => {
        buf.push(0xFF);
        buf.extend_from_slice(&self.0.to_le_bytes());
      }
    }
  }
}

impl CompactSize {
  /// Wraps an integer for CompactSize encoding.
  pub const fn new(value: u64) -> Self {
    Self(value)
  }

  /// Reads a length or count prefix. A prefix above [`MAX_SIZE`] or past the
  /// end of the input fails before the caller allocates for it.
  ///
  /// # Errors
  ///
  /// Returns [`DecodeError::CompactSizeExceedsLimit`] when the value exceeds
  /// [`MAX_SIZE`], [`DecodeError::Eof`] when it exceeds the bytes left after
  /// the prefix, and any error of [`BaseCodec::decode`].
  pub fn decode_len(data: &mut &[u8]) -> Result<usize, DecodeError> {
    let value = Self::decode_checked(data)?.0;
    match usize::try_from(value) {
      Ok(len) if len <= data.len() => Ok(len),
      _ => Err(DecodeError::Eof {
        needed: usize::try_from(value).unwrap_or(usize::MAX),
        remaining: data.len(),
      }),
    }
  }

  /// Reads a CompactSize-encoded integer field that the format bounds by
  /// [`MAX_SIZE`]. Length and count prefixes read through
  /// [`CompactSize::decode_len`].
  ///
  /// # Errors
  ///
  /// Returns [`DecodeError::CompactSizeExceedsLimit`] when the value exceeds
  /// [`MAX_SIZE`], and any error of [`BaseCodec::decode`].
  pub fn decode_checked(data: &mut &[u8]) -> Result<Self, DecodeError> {
    let value = Self::decode(data)?;
    if value.0 > MAX_SIZE {
      return Err(DecodeError::CompactSizeExceedsLimit {
        limit: MAX_SIZE as usize,
        value: value.0,
      });
    }
    Ok(value)
  }

  /// Reads a CompactSize-encoded integer field of type `T` that the format
  /// leaves unbounded by [`MAX_SIZE`].
  ///
  /// # Errors
  ///
  /// Returns [`DecodeError::CompactSizeExceedsLimit`] when the value exceeds
  /// the maximum of `T`, and any error of [`BaseCodec::decode`].
  pub fn decode_as<T: CompactUint>(data: &mut &[u8]) -> Result<T, DecodeError> {
    Self::decode(data)?.into_uint()
  }

  /// Reads a CompactSize-encoded integer field of type `T` that the format
  /// also bounds by [`MAX_SIZE`].
  ///
  /// # Errors
  ///
  /// Returns [`DecodeError::CompactSizeExceedsLimit`] when the value exceeds
  /// [`MAX_SIZE`] or the maximum of `T`, and any error of
  /// [`BaseCodec::decode`].
  pub fn decode_checked_as<T: CompactUint>(data: &mut &[u8]) -> Result<T, DecodeError> {
    Self::decode_checked(data)?.into_uint()
  }

  fn into_uint<T: CompactUint>(self) -> Result<T, DecodeError> {
    T::from_u64(self.0).ok_or(DecodeError::CompactSizeExceedsLimit {
      limit: usize::try_from(T::MAX).unwrap_or(usize::MAX),
      value: self.0,
    })
  }

  /// Bounds a length or count by a protocol limit. A prefix bounded only by
  /// the input reads through [`CompactSize::decode_len`].
  ///
  /// # Errors
  ///
  /// Returns [`DecodeError::CompactSizeExceedsLimit`] when the value does not
  /// fit in `usize` or exceeds `limit`.
  pub fn into_len(self, limit: usize) -> Result<usize, DecodeError> {
    let value = self.0;
    let len = usize::try_from(value).map_err(|_| DecodeError::CompactSizeExceedsLimit { limit, value })?;
    if len > limit {
      return Err(DecodeError::CompactSizeExceedsLimit { limit, value });
    }
    Ok(len)
  }
}

impl From<u64> for CompactSize {
  fn from(value: u64) -> Self {
    Self(value)
  }
}

impl From<usize> for CompactSize {
  fn from(value: usize) -> Self {
    Self(value as u64)
  }
}

impl From<CompactSize> for u64 {
  fn from(value: CompactSize) -> Self {
    value.0
  }
}

#[cfg(test)]
mod tests {
  use super::{CompactSize, MAX_SIZE};
  use crate::codec::{BaseCodec, DecodeError};
  use crate::prelude::*;
  use crate::Numeric;

  use rstest::*;

  #[rstest]
  #[case::single_min(0, &[0x00])]
  #[case::single_max(0xFC, &[0xFC])]
  #[case::u16_min(0xFD, &[0xFD, 0xFD, 0x00])]
  #[case::u16_max(0xFFFF, &[0xFD, 0xFF, 0xFF])]
  #[case::u32_min(0x1_0000, &[0xFE, 0x00, 0x00, 0x01, 0x00])]
  #[case::u32_max(0xFFFF_FFFF, &[0xFE, 0xFF, 0xFF, 0xFF, 0xFF])]
  #[case::u64_min(0x1_0000_0000, &[0xFF, 0, 0, 0, 0, 0x01, 0, 0, 0])]
  #[case::u64_max(u64::MAX, &[0xFF; 9])]
  fn roundtrips_at_every_width_boundary(#[case] value: u64, #[case] wire: &[u8]) {
    let mut buf = Vec::new();
    CompactSize::new(value).encode(&mut buf);
    assert_eq!(buf, wire, "encoding {value:#x}");

    let mut cursor = wire;
    assert_eq!(CompactSize::decode(&mut cursor).map(|v| v.to_base()), Ok(value));
    assert!(cursor.is_empty(), "decode left {} bytes", cursor.len());
  }

  #[rstest]
  #[case::u16_holds_single(&[0xFD, 0xFC, 0x00], 0xFC)]
  #[case::u32_holds_u16(&[0xFE, 0xFF, 0xFF, 0x00, 0x00], 0xFFFF)]
  #[case::u64_holds_u32(&[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0, 0, 0, 0], 0xFFFF_FFFF)]
  fn rejects_non_minimal_encodings(#[case] wire: &[u8], #[case] value: u64) {
    assert_eq!(
      CompactSize::decode(&mut &*wire),
      Err(DecodeError::NonMinimalCompactSize { value })
    );
  }

  #[rstest]
  #[case::marker_only(&[0xFD])]
  #[case::short_u32(&[0xFE, 0x00, 0x00])]
  #[case::short_u64(&[0xFF, 0x00, 0x00, 0x00, 0x00])]
  fn rejects_truncated_input(#[case] wire: &[u8]) {
    assert!(matches!(CompactSize::decode(&mut &*wire), Err(DecodeError::Eof { .. })));
  }

  #[rstest]
  fn into_len_enforces_the_caller_limit() {
    assert_eq!(CompactSize::new(8).into_len(8), Ok(8));
    assert_eq!(
      CompactSize::new(9).into_len(8),
      Err(DecodeError::CompactSizeExceedsLimit { limit: 8, value: 9 })
    );
    // A count field with no room to spare still admits the empty case.
    assert_eq!(CompactSize::new(0).into_len(0), Ok(0));
  }

  fn prefixed(value: u64, remaining: usize) -> Vec<u8> {
    let mut buf = Vec::new();
    CompactSize::new(value).encode(&mut buf);
    buf.resize(buf.len() + remaining, 0);
    buf
  }

  #[rstest]
  #[case::empty(0, 0)]
  #[case::exact(4, 4)]
  #[case::spare(3, 4)]
  fn decode_len_admits_lengths_within_the_input(#[case] value: u64, #[case] remaining: usize) {
    let wire = prefixed(value, remaining);
    let mut cursor = wire.as_slice();
    assert_eq!(CompactSize::decode_len(&mut cursor), Ok(value as usize));
    assert_eq!(cursor.len(), remaining, "decode_len consumes only the prefix");
  }

  #[rstest]
  #[case::one_past(5, 4, 5)]
  #[case::empty_input(1, 0, 1)]
  #[case::max_size(MAX_SIZE, 4, MAX_SIZE as usize)]
  fn decode_len_reports_eof_past_the_input(#[case] value: u64, #[case] remaining: usize, #[case] needed: usize) {
    let wire = prefixed(value, remaining);
    assert_eq!(
      CompactSize::decode_len(&mut wire.as_slice()),
      Err(DecodeError::Eof { needed, remaining })
    );
  }

  fn exceeds(limit: u64, value: u64) -> DecodeError {
    DecodeError::CompactSizeExceedsLimit {
      limit: usize::try_from(limit).unwrap_or(usize::MAX),
      value,
    }
  }

  #[rstest]
  #[case::zero(0, Ok(0))]
  #[case::max_size(MAX_SIZE, Ok(MAX_SIZE))]
  #[case::past_max_size(MAX_SIZE + 1, Err(exceeds(MAX_SIZE, MAX_SIZE + 1)))]
  #[case::u64_max(u64::MAX, Err(exceeds(MAX_SIZE, u64::MAX)))]
  fn decode_checked_rejects_values_past_max_size(#[case] value: u64, #[case] expected: Result<u64, DecodeError>) {
    let wire = prefixed(value, 0);
    assert_eq!(
      CompactSize::decode_checked(&mut wire.as_slice()).map(|v| v.to_base()),
      expected
    );
  }

  /// The range check runs before the input bound, so an oversized prefix
  /// reports the limit even when the input is short.
  #[rstest]
  #[case::past_max_size(MAX_SIZE + 1)]
  #[case::u64_max(u64::MAX)]
  fn decode_len_rejects_prefixes_past_max_size(#[case] value: u64) {
    let wire = prefixed(value, 1);
    assert_eq!(
      CompactSize::decode_len(&mut wire.as_slice()),
      Err(exceeds(MAX_SIZE, value))
    );
  }

  #[rstest]
  fn decode_as_bounds_the_value_by_the_type() {
    let read_u8 = |v: u64| CompactSize::decode_as::<u8>(&mut prefixed(v, 0).as_slice());
    let read_u16 = |v: u64| CompactSize::decode_as::<u16>(&mut prefixed(v, 0).as_slice());
    let read_u32 = |v: u64| CompactSize::decode_as::<u32>(&mut prefixed(v, 0).as_slice());
    let read_u64 = |v: u64| CompactSize::decode_as::<u64>(&mut prefixed(v, 0).as_slice());

    assert_eq!(read_u8(0xFF), Ok(u8::MAX));
    assert_eq!(read_u8(0x100), Err(exceeds(0xFF, 0x100)));
    assert_eq!(read_u16(0xFFFF), Ok(u16::MAX));
    assert_eq!(read_u16(0x1_0000), Err(exceeds(0xFFFF, 0x1_0000)));
    assert_eq!(read_u32(0xFFFF_FFFF), Ok(u32::MAX));
    assert_eq!(read_u32(0x1_0000_0000), Err(exceeds(0xFFFF_FFFF, 0x1_0000_0000)));
    assert_eq!(read_u64(u64::MAX), Ok(u64::MAX));
  }

  #[rstest]
  fn decode_checked_as_applies_max_size_before_the_type() {
    let read_u8 = |v: u64| CompactSize::decode_checked_as::<u8>(&mut prefixed(v, 0).as_slice());
    let read_u32 = |v: u64| CompactSize::decode_checked_as::<u32>(&mut prefixed(v, 0).as_slice());
    let read_u64 = |v: u64| CompactSize::decode_checked_as::<u64>(&mut prefixed(v, 0).as_slice());

    assert_eq!(read_u8(0xFF), Ok(u8::MAX));
    assert_eq!(read_u8(0x100), Err(exceeds(0xFF, 0x100)));
    assert_eq!(read_u8(MAX_SIZE + 1), Err(exceeds(MAX_SIZE, MAX_SIZE + 1)));
    assert_eq!(read_u32(MAX_SIZE), Ok(0x0200_0000));
    assert_eq!(read_u32(MAX_SIZE + 1), Err(exceeds(MAX_SIZE, MAX_SIZE + 1)));
    assert_eq!(read_u64(u64::MAX), Err(exceeds(MAX_SIZE, u64::MAX)));
  }

  #[rstest]
  fn typed_reads_propagate_decode_errors() {
    assert!(matches!(
      CompactSize::decode_checked_as::<u32>(&mut &[0xFD][..]),
      Err(DecodeError::Eof { .. })
    ));
    assert_eq!(
      CompactSize::decode_as::<u16>(&mut &[0xFD, 0xFC, 0x00][..]),
      Err(DecodeError::NonMinimalCompactSize { value: 0xFC })
    );
  }

  #[rstest]
  fn conversions_preserve_the_value() {
    assert_eq!(u64::from(CompactSize::from(0xDEAD_u64)), 0xDEAD);
    assert_eq!(CompactSize::from(7usize).to_base(), 7);
  }
}
