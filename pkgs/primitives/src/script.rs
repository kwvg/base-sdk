//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Variable-length script with CompactSize-prefixed consensus encoding.

use crate::prelude::*;

use bitcoin_consensus_encoding as encoding;

use core::fmt;

/// Maximum serialized object size (32 MiB).
const MAX_SIZE: usize = 0x0200_0000;

/// A variable-length script, CompactSize-prefixed on the wire.
#[derive(Clone, PartialEq, Eq, Hash, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(transparent))]
pub struct Script(#[cfg_attr(feature = "serde", serde(with = "dash_types::serialize::hex"))] pub Vec<u8>);

impl Script {
  /// Creates a new script from raw bytes.
  pub fn new(data: Vec<u8>) -> Self {
    Self(data)
  }

  /// Returns a reference to the script bytes.
  pub fn as_bytes(&self) -> &[u8] {
    &self.0
  }

  /// Returns the length in bytes.
  pub fn len(&self) -> usize {
    self.0.len()
  }

  /// Returns whether the script is empty.
  pub fn is_empty(&self) -> bool {
    self.0.is_empty()
  }
}

impl fmt::Debug for Script {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "Script(")?;
    for byte in &self.0 {
      write!(f, "{:02x}", byte)?;
    }
    write!(f, ")")
  }
}

impl fmt::Display for Script {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    for byte in &self.0 {
      write!(f, "{:02x}", byte)?;
    }
    Ok(())
  }
}

// Consensus encoding (new ecosystem traits).

encoding::encoder_newtype! {
  /// Encoder for [`Script`].
  pub struct ScriptEncoder<'e>(
    encoding::Encoder2<encoding::CompactSizeEncoder, encoding::BytesEncoder<'e>>
  );
}

impl encoding::Encodable for Script {
  type Encoder<'e> = ScriptEncoder<'e>;

  fn encoder(&self) -> Self::Encoder<'_> {
    ScriptEncoder::new(encoding::Encoder2::new(
      encoding::CompactSizeEncoder::new(self.0.len()),
      encoding::BytesEncoder::without_length_prefix(&self.0),
    ))
  }
}

/// Decoder for [`Script`].
#[derive(Debug)]
pub struct ScriptDecoder(encoding::ByteVecDecoder);

impl ScriptDecoder {
  /// Constructs a new decoder with the default script size limit.
  pub const fn new() -> Self {
    Self(encoding::ByteVecDecoder::new_with_limit(MAX_SIZE))
  }
}

impl Default for ScriptDecoder {
  fn default() -> Self {
    Self::new()
  }
}

/// Decode error for [`Script`].
#[derive(Debug)]
pub struct ScriptDecoderError(encoding::ByteVecDecoderError);

impl fmt::Display for ScriptDecoderError {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "script decode failed: {}", self.0)
  }
}

impl encoding::Decoder for ScriptDecoder {
  type Output = Script;
  type Error = ScriptDecoderError;

  #[inline]
  fn push_bytes(&mut self, bytes: &mut &[u8]) -> Result<bool, Self::Error> {
    self.0.push_bytes(bytes).map_err(ScriptDecoderError)
  }

  #[inline]
  fn end(self) -> Result<Self::Output, Self::Error> {
    self.0.end().map(Script).map_err(ScriptDecoderError)
  }

  #[inline]
  fn read_limit(&self) -> usize {
    self.0.read_limit()
  }
}

impl encoding::Decodable for Script {
  type Decoder = ScriptDecoder;
  fn decoder() -> Self::Decoder {
    ScriptDecoder::new()
  }
}

/// Encodes a `usize` as a CompactSize integer.
pub(crate) fn encode_compact_size(value: usize, buf: &mut Vec<u8>) {
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
