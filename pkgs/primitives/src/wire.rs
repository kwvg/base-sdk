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

use dash_types::codec::{read_bytes, read_compact_size, read_u16_be, take, DecodeError};

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
