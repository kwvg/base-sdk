//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Ping and Pong keepalive messages.

use bitcoin_consensus_encoding as encoding;

use core::fmt;

/// Keepalive request carrying a random nonce.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct Ping {
  /// Random nonce echoed back in the corresponding `Pong`.
  pub nonce: u64,
}

encoding::encoder_newtype_exact! {
  /// Encoder for [`Ping`].
  pub struct PingEncoder<'e>(encoding::ArrayEncoder<8>);
}

impl encoding::Encodable for Ping {
  type Encoder<'e> = PingEncoder<'e>;
  fn encoder(&self) -> Self::Encoder<'_> {
    PingEncoder::new(encoding::ArrayEncoder::without_length_prefix(self.nonce.to_le_bytes()))
  }
}

/// Decoder for [`Ping`].
#[derive(Clone, Debug)]
pub struct PingDecoder(encoding::ArrayDecoder<8>);

impl PingDecoder {
  /// Creates a new decoder.
  pub const fn new() -> Self {
    Self(encoding::ArrayDecoder::new())
  }
}

impl Default for PingDecoder {
  fn default() -> Self {
    Self::new()
  }
}

/// Decode error for [`Ping`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PingDecoderError(encoding::UnexpectedEofError);

impl fmt::Display for PingDecoderError {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "ping decode: {}", self.0)
  }
}

impl encoding::Decoder for PingDecoder {
  type Output = Ping;
  type Error = PingDecoderError;

  fn push_bytes(&mut self, bytes: &mut &[u8]) -> Result<bool, Self::Error> {
    self.0.push_bytes(bytes).map_err(PingDecoderError)
  }

  fn end(self) -> Result<Self::Output, Self::Error> {
    let buf = self.0.end().map_err(PingDecoderError)?;
    Ok(Ping {
      nonce: u64::from_le_bytes(buf),
    })
  }

  fn read_limit(&self) -> usize {
    self.0.read_limit()
  }
}

impl encoding::Decodable for Ping {
  type Decoder = PingDecoder;
  fn decoder() -> Self::Decoder {
    PingDecoder::new()
  }
}

/// Keepalive response echoing the nonce from a `Ping`.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct Pong {
  /// Nonce from the original `Ping`.
  pub nonce: u64,
}

encoding::encoder_newtype_exact! {
  /// Encoder for [`Pong`].
  pub struct PongEncoder<'e>(encoding::ArrayEncoder<8>);
}

impl encoding::Encodable for Pong {
  type Encoder<'e> = PongEncoder<'e>;
  fn encoder(&self) -> Self::Encoder<'_> {
    PongEncoder::new(encoding::ArrayEncoder::without_length_prefix(self.nonce.to_le_bytes()))
  }
}

/// Decoder for [`Pong`].
#[derive(Clone, Debug)]
pub struct PongDecoder(encoding::ArrayDecoder<8>);

impl PongDecoder {
  /// Creates a new decoder.
  pub const fn new() -> Self {
    Self(encoding::ArrayDecoder::new())
  }
}

impl Default for PongDecoder {
  fn default() -> Self {
    Self::new()
  }
}

/// Decode error for [`Pong`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PongDecoderError(encoding::UnexpectedEofError);

impl fmt::Display for PongDecoderError {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "pong decode: {}", self.0)
  }
}

impl encoding::Decoder for PongDecoder {
  type Output = Pong;
  type Error = PongDecoderError;

  fn push_bytes(&mut self, bytes: &mut &[u8]) -> Result<bool, Self::Error> {
    self.0.push_bytes(bytes).map_err(PongDecoderError)
  }

  fn end(self) -> Result<Self::Output, Self::Error> {
    let buf = self.0.end().map_err(PongDecoderError)?;
    Ok(Pong {
      nonce: u64::from_le_bytes(buf),
    })
  }

  fn read_limit(&self) -> usize {
    self.0.read_limit()
  }
}

impl encoding::Decodable for Pong {
  type Decoder = PongDecoder;
  fn decoder() -> Self::Decoder {
    PongDecoder::new()
  }
}
