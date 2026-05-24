//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Low-level wire-format reading helpers.
//!
//! Functions advance a `&mut &[u8]` slice reference, consuming bytes as they
//! decode. This matches the convention used by
//! `bitcoin_consensus_encoding::decode_from_slice_unbounded`.

use crate::prelude::*;

use dash_types::codec::DecodeError;

fn ensure(sl: &[u8], n: usize) -> Result<(), DecodeError> {
  if sl.len() < n {
    Err(DecodeError::Eof {
      needed: n,
      remaining: sl.len(),
    })
  } else {
    Ok(())
  }
}

fn take<const N: usize>(sl: &mut &[u8]) -> Result<[u8; N], DecodeError> {
  ensure(sl, N)?;
  let mut arr = [0u8; N];
  arr.copy_from_slice(&sl[..N]);
  *sl = &sl[N..];
  Ok(arr)
}

/// Reads a single byte.
pub fn read_u8(sl: &mut &[u8]) -> Result<u8, DecodeError> {
  Ok(take::<1>(sl)?[0])
}

/// Reads a single byte as a bool (0 = false, nonzero = true).
pub fn read_bool(sl: &mut &[u8]) -> Result<bool, DecodeError> {
  read_u8(sl).map(|b| b != 0)
}

/// Reads a little-endian `u16`.
pub fn read_u16_le(sl: &mut &[u8]) -> Result<u16, DecodeError> {
  take::<2>(sl).map(u16::from_le_bytes)
}

/// Reads a big-endian `u16` (used for network ports).
pub fn read_u16_be(sl: &mut &[u8]) -> Result<u16, DecodeError> {
  take::<2>(sl).map(u16::from_be_bytes)
}

/// Reads a little-endian `u32`.
pub fn read_u32_le(sl: &mut &[u8]) -> Result<u32, DecodeError> {
  take::<4>(sl).map(u32::from_le_bytes)
}

/// Reads a little-endian `u64`.
pub fn read_u64_le(sl: &mut &[u8]) -> Result<u64, DecodeError> {
  take::<8>(sl).map(u64::from_le_bytes)
}

/// Reads a little-endian `i16`.
pub fn read_i16_le(sl: &mut &[u8]) -> Result<i16, DecodeError> {
  take::<2>(sl).map(i16::from_le_bytes)
}

/// Reads a little-endian `i32`.
pub fn read_i32_le(sl: &mut &[u8]) -> Result<i32, DecodeError> {
  take::<4>(sl).map(i32::from_le_bytes)
}

/// Reads a little-endian `i64`.
pub fn read_i64_le(sl: &mut &[u8]) -> Result<i64, DecodeError> {
  take::<8>(sl).map(i64::from_le_bytes)
}

/// Reads exactly `N` bytes into a fixed-size array.
pub fn read_array<const N: usize>(sl: &mut &[u8]) -> Result<[u8; N], DecodeError> {
  take::<N>(sl)
}

/// Reads exactly `n` bytes as a sub-slice (zero-copy).
pub fn read_bytes<'a>(sl: &mut &'a [u8], n: usize) -> Result<&'a [u8], DecodeError> {
  ensure(sl, n)?;
  let (head, rest) = sl.split_at(n);
  *sl = rest;
  Ok(head)
}

/// Reads a `Hash256` (32 bytes, wire order).
pub fn read_hash(sl: &mut &[u8]) -> Result<dash_num::Hash256, DecodeError> {
  take::<32>(sl).map(dash_num::Hash256::from_bytes)
}

/// Reads a fixed-size byte newtype via `From<[u8; N]>`.
pub fn read_type<T, const N: usize>(sl: &mut &[u8]) -> Result<T, DecodeError>
where
  T: From<[u8; N]>,
{
  take::<N>(sl).map(T::from)
}

/// Reads a CompactSize-encoded `u64` with minimal encoding check.
pub fn read_compact_u64(sl: &mut &[u8]) -> Result<u64, DecodeError> {
  let first = read_u8(sl)?;
  match first {
    0..=0xFC => Ok(u64::from(first)),
    0xFD => {
      let v = read_u16_le(sl)?;
      if v < 0xFD {
        return Err(DecodeError::NonMinimalCompactSize { value: u64::from(v) });
      }
      Ok(u64::from(v))
    }
    0xFE => {
      let v = read_u32_le(sl)?;
      if v < 0x10000 {
        return Err(DecodeError::NonMinimalCompactSize { value: u64::from(v) });
      }
      Ok(u64::from(v))
    }
    0xFF => {
      let v = read_u64_le(sl)?;
      if v < 0x1_0000_0000 {
        return Err(DecodeError::NonMinimalCompactSize { value: v });
      }
      Ok(v)
    }
  }
}

/// Reads a CompactSize-encoded length with a limit.
pub fn read_compact_size(sl: &mut &[u8], limit: usize) -> Result<usize, DecodeError> {
  let value = read_compact_u64(sl)?;
  let n = usize::try_from(value).map_err(|_| DecodeError::CompactSizeExceedsLimit { limit, value })?;
  if n > limit {
    return Err(DecodeError::CompactSizeExceedsLimit { limit, value });
  }
  Ok(n)
}

/// Reads a CompactSize-prefixed `Script`.
pub fn read_script(sl: &mut &[u8], limit: usize) -> Result<crate::script::Script, DecodeError> {
  let len = read_compact_size(sl, limit)?;
  let bytes = read_bytes(sl, len)?;
  Ok(crate::script::Script::new(bytes.to_vec()))
}

/// Reads a CompactSize-prefixed byte vector.
pub fn read_vec(sl: &mut &[u8], limit: usize) -> Result<Vec<u8>, DecodeError> {
  let len = read_compact_size(sl, limit)?;
  Ok(read_bytes(sl, len)?.to_vec())
}

/// Reads a `DynBitset`.
pub fn read_dynbitset(sl: &mut &[u8], max_bits: usize) -> Result<crate::support::DynBitset, DecodeError> {
  let num_bits = read_compact_size(sl, max_bits)? as u64;
  let byte_len = num_bits.div_ceil(8) as usize;
  let data = read_bytes(sl, byte_len)?.to_vec();
  Ok(crate::support::DynBitset { num_bits, data })
}

/// Reads a legacy `CService`.
pub fn read_cservice(sl: &mut &[u8]) -> Result<crate::support::CService, DecodeError> {
  Ok(crate::support::CService {
    addr: take::<16>(sl)?,
    port: read_u16_be(sl)?,
  })
}
