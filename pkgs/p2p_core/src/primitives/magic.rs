//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Dash network magic bytes.

use bitcoin_consensus_encoding as encoding;
use dash_params::types::MessageStart;

use core::fmt;

/// Four-byte network identifier prepended to every V1 message.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Magic(pub [u8; 4]);

impl Magic {
  /// Returns the inner byte array.
  pub const fn to_byte_array(self) -> [u8; 4] {
    self.0
  }

  /// Returns a reference to the inner byte array.
  pub const fn as_byte_array(&self) -> &[u8; 4] {
    &self.0
  }
}

impl From<MessageStart> for Magic {
  fn from(ms: MessageStart) -> Self {
    Self(ms)
  }
}

impl From<Magic> for [u8; 4] {
  fn from(val: Magic) -> Self {
    val.0
  }
}

impl AsRef<[u8]> for Magic {
  fn as_ref(&self) -> &[u8] {
    &self.0
  }
}

impl fmt::Debug for Magic {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "Magic(")?;
    for byte in &self.0 {
      write!(f, "{:02x}", byte)?;
    }
    write!(f, ")")
  }
}

impl fmt::Display for Magic {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    for byte in &self.0 {
      write!(f, "{:02x}", byte)?;
    }
    Ok(())
  }
}

encoding::encoder_newtype_exact! {
  /// Encoder for [`Magic`].
  pub struct MagicEncoder<'e>(encoding::ArrayEncoder<4>);
}

impl encoding::Encodable for Magic {
  type Encoder<'e> = MagicEncoder<'e>;
  fn encoder(&self) -> Self::Encoder<'_> {
    MagicEncoder::new(encoding::ArrayEncoder::without_length_prefix(self.0))
  }
}

/// Decoder for [`Magic`].
#[derive(Debug)]
pub struct MagicDecoder(encoding::ArrayDecoder<4>);

impl MagicDecoder {
  /// Creates a new decoder.
  pub const fn new() -> Self {
    Self(encoding::ArrayDecoder::new())
  }
}

impl Default for MagicDecoder {
  fn default() -> Self {
    Self::new()
  }
}

/// Decode error for [`Magic`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MagicDecoderError(encoding::UnexpectedEofError);

impl fmt::Display for MagicDecoderError {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "magic decode: {}", self.0)
  }
}

impl encoding::Decoder for MagicDecoder {
  type Output = Magic;
  type Error = MagicDecoderError;

  fn push_bytes(&mut self, bytes: &mut &[u8]) -> Result<bool, Self::Error> {
    self.0.push_bytes(bytes).map_err(MagicDecoderError)
  }

  fn end(self) -> Result<Self::Output, Self::Error> {
    let buf = self.0.end().map_err(MagicDecoderError)?;
    Ok(Magic(buf))
  }

  fn read_limit(&self) -> usize {
    self.0.read_limit()
  }
}

impl encoding::Decodable for Magic {
  type Decoder = MagicDecoder;
  fn decoder() -> Self::Decoder {
    MagicDecoder::new()
  }
}
