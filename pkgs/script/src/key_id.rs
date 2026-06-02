//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Public key hash identifier (HASH160).

use bitcoin_consensus_encoding as encoding;

use core::fmt;

/// 20-byte public key hash (RIPEMD-160 of SHA-256).
#[derive(Clone, Copy, Default, Eq, Hash, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(transparent))]
pub struct KeyId(#[cfg_attr(feature = "serde", serde(with = "dash_types::serialize::hex::w20"))] pub [u8; 20]);

impl KeyId {
  /// Returns the inner byte array.
  pub const fn to_bytes(self) -> [u8; 20] {
    self.0
  }

  /// Borrows the inner byte array.
  pub const fn as_bytes(&self) -> &[u8; 20] {
    &self.0
  }

  /// Returns `true` when every byte is zero.
  pub fn is_null(&self) -> bool {
    self.0.iter().all(|&b| b == 0)
  }
}

impl From<[u8; 20]> for KeyId {
  fn from(bytes: [u8; 20]) -> Self {
    Self(bytes)
  }
}

impl From<KeyId> for [u8; 20] {
  fn from(val: KeyId) -> Self {
    val.0
  }
}

impl AsRef<[u8]> for KeyId {
  fn as_ref(&self) -> &[u8] {
    &self.0
  }
}

impl AsRef<[u8; 20]> for KeyId {
  fn as_ref(&self) -> &[u8; 20] {
    &self.0
  }
}

impl fmt::Debug for KeyId {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "KeyId(")?;
    for byte in &self.0 {
      write!(f, "{:02x}", byte)?;
    }
    write!(f, ")")
  }
}

impl fmt::Display for KeyId {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    for byte in &self.0 {
      write!(f, "{:02x}", byte)?;
    }
    Ok(())
  }
}

// Consensus encoding.

impl encoding::Encodable for KeyId {
  type Encoder<'e> = encoding::ArrayRefEncoder<'e, 20>;

  fn encoder(&self) -> Self::Encoder<'_> {
    encoding::ArrayRefEncoder::without_length_prefix(&self.0)
  }
}

/// Decoder for [`KeyId`].
#[derive(Clone, Debug)]
pub struct KeyIdDecoder(encoding::ArrayDecoder<20>);

impl KeyIdDecoder {
  /// Constructs a new decoder.
  pub const fn new() -> Self {
    Self(encoding::ArrayDecoder::new())
  }
}

impl Default for KeyIdDecoder {
  fn default() -> Self {
    Self::new()
  }
}

/// Decode error for [`KeyId`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KeyIdDecoderError(encoding::UnexpectedEofError);

impl fmt::Display for KeyIdDecoderError {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "key id decode: {}", self.0)
  }
}

impl encoding::Decoder for KeyIdDecoder {
  type Output = KeyId;
  type Error = KeyIdDecoderError;

  #[inline]
  fn push_bytes(&mut self, bytes: &mut &[u8]) -> Result<bool, Self::Error> {
    self.0.push_bytes(bytes).map_err(KeyIdDecoderError)
  }

  #[inline]
  fn end(self) -> Result<Self::Output, Self::Error> {
    self.0.end().map(KeyId).map_err(KeyIdDecoderError)
  }

  #[inline]
  fn read_limit(&self) -> usize {
    self.0.read_limit()
  }
}

impl encoding::Decodable for KeyId {
  type Decoder = KeyIdDecoder;
  fn decoder() -> Self::Decoder {
    KeyIdDecoder::new()
  }
}
