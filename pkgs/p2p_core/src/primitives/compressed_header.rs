//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! DIP-0025 compressed block header (headers2 format).

use crate::encode::WireDecodeError;
use crate::prelude::*;

use dash_primitives::wire;
use dash_primitives::{BlockHash, BlockHeader, MerkleRoot};

// Bitfield layout (1 byte):
//   bits 0-2: version offset (0 = full version present, 1-7 = MRU cache index)
//   bit 3:    prev_blockhash present
//   bit 4:    timestamp mode (0 = i16 delta, 1 = full u32)
//   bit 5:    nbits present
const VERSION_OFFSET_MASK: u8 = 0b0000_0111;
const FLAG_PREV_HASH: u8 = 0b0000_1000;
const FLAG_TIMESTAMP_FULL: u8 = 0b0001_0000;
const FLAG_NBITS: u8 = 0b0010_0000;

/// Maximum entries in the MRU version cache.
const MAX_VERSION_CACHE: usize = 7;

/// Stateful compressor/decompressor for a stream of block headers.
///
/// The DIP-0025 encoding is inherently sequential: each header is
/// delta-encoded against its predecessor and a shared MRU version
/// cache. Create one `CompressionState` per `headers2` message and
/// feed headers through it in order.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct CompressionState {
  /// MRU version cache (front = most recently used).
  pub version_cache: Vec<i32>,
  /// Previous fully-resolved header.
  pub prev_header: Option<BlockHeader>,
}

impl Default for CompressionState {
  fn default() -> Self {
    Self::new()
  }
}

impl CompressionState {
  /// Creates fresh state with an empty cache and no previous header.
  pub fn new() -> Self {
    Self {
      version_cache: Vec::with_capacity(MAX_VERSION_CACHE),
      prev_header: None,
    }
  }

  /// Moves the version at `position` to the front of the cache.
  fn mark_version_mru(&mut self, position: usize) {
    let v = self.version_cache.remove(position);
    self.version_cache.insert(0, v);
  }

  /// Inserts `version` at the front, evicting the oldest if full.
  fn save_version_mru(&mut self, version: i32) {
    if self.version_cache.len() >= MAX_VERSION_CACHE {
      self.version_cache.pop();
    }
    self.version_cache.insert(0, version);
  }

  /// Finds the cache position (0-based) for a version, if cached.
  fn find_version(&self, version: i32) -> Option<usize> {
    self.version_cache.iter().position(|&v| v == version)
  }

  /// Decodes one compressed header, advancing the slice and state.
  pub(crate) fn decode_header(&mut self, sl: &mut &[u8]) -> Result<BlockHeader, WireDecodeError> {
    let flags = wire::read_u8(sl)?;
    let version_offset = flags & VERSION_OFFSET_MASK;

    let version = if version_offset == 0 {
      let v = wire::read_i32_le(sl)?;
      self.save_version_mru(v);
      v
    } else {
      let pos = (version_offset - 1) as usize;
      if pos >= self.version_cache.len() {
        return Err(WireDecodeError(format!("version offset {pos} out of range")));
      }
      let v = self.version_cache[pos];
      self.mark_version_mru(pos);
      v
    };

    let prev_hash = if flags & FLAG_PREV_HASH != 0 {
      BlockHash::from_bytes(wire::read_array(sl)?)
    } else {
      match &self.prev_header {
        Some(prev) => prev.prev_hash,
        None => BlockHash::default(),
      }
    };

    let merkle_root = MerkleRoot::from_bytes(wire::read_array(sl)?);

    let time = if flags & FLAG_TIMESTAMP_FULL != 0 {
      wire::read_u32_le(sl)?
    } else {
      let delta = wire::read_i16_le(sl)?;
      match &self.prev_header {
        Some(prev) => (prev.time as i64 + delta as i64) as u32,
        None => delta as u32,
      }
    };

    let bits = if flags & FLAG_NBITS != 0 {
      wire::read_u32_le(sl)?
    } else {
      match &self.prev_header {
        Some(prev) => prev.bits,
        None => 0,
      }
    };

    let nonce = wire::read_u32_le(sl)?;

    let header = BlockHeader {
      version,
      prev_hash,
      merkle_root,
      time,
      bits,
      nonce,
    };
    self.prev_header = Some(header);
    Ok(header)
  }

  /// Encodes one header in compressed form, advancing the state.
  pub fn encode_header(&mut self, header: &BlockHeader, buf: &mut Vec<u8>) {
    let mut flags: u8 = 0;

    let version_offset = match self.find_version(header.version) {
      Some(pos) => (pos + 1) as u8,
      None => 0,
    };
    flags |= version_offset & VERSION_OFFSET_MASK;

    let need_prev_hash = match &self.prev_header {
      Some(prev) => header.prev_hash != prev.prev_hash,
      None => true,
    };
    if need_prev_hash {
      flags |= FLAG_PREV_HASH;
    }

    let time_delta = match &self.prev_header {
      Some(prev) => {
        let d = header.time as i64 - prev.time as i64;
        if (i16::MIN as i64..=i16::MAX as i64).contains(&d) {
          Some(d as i16)
        } else {
          None
        }
      }
      None => None,
    };
    if time_delta.is_none() {
      flags |= FLAG_TIMESTAMP_FULL;
    }

    let need_nbits = match &self.prev_header {
      Some(prev) => header.bits != prev.bits,
      None => true,
    };
    if need_nbits {
      flags |= FLAG_NBITS;
    }

    buf.push(flags);

    if version_offset == 0 {
      buf.extend_from_slice(&header.version.to_le_bytes());
      self.save_version_mru(header.version);
    } else {
      let pos = (version_offset - 1) as usize;
      self.mark_version_mru(pos);
    }

    if need_prev_hash {
      buf.extend_from_slice(&header.prev_hash.to_bytes());
    }

    buf.extend_from_slice(&header.merkle_root.to_bytes());

    match time_delta {
      Some(d) => buf.extend_from_slice(&d.to_le_bytes()),
      None => buf.extend_from_slice(&header.time.to_le_bytes()),
    }

    if need_nbits {
      buf.extend_from_slice(&header.bits.to_le_bytes());
    }

    buf.extend_from_slice(&header.nonce.to_le_bytes());
    self.prev_header = Some(*header);
  }
}
