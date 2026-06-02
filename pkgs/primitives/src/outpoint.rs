//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Transaction outpoint (36 bytes).

use crate::TxHash;

use bitcoin_consensus_encoding as encoding;
use bitcoin_internals::array::ArrayExt as _;

use core::fmt;

/// A reference to a previous transaction output.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct OutPoint {
  /// Transaction hash of the referenced output.
  pub hash: TxHash,
  /// Index of the referenced output within the transaction.
  pub index: u32,
}

impl fmt::Display for OutPoint {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "{}:{}", self.hash, self.index)
  }
}

// Consensus encoding (new ecosystem traits).

encoding::encoder_newtype_exact! {
  /// Encoder for [`OutPoint`].
  pub struct OutPointEncoder<'e>(encoding::Encoder2<encoding::BytesEncoder<'e>, encoding::ArrayEncoder<4>>);
}

impl encoding::Encodable for OutPoint {
  type Encoder<'e> = OutPointEncoder<'e>;

  fn encoder(&self) -> Self::Encoder<'_> {
    OutPointEncoder::new(encoding::Encoder2::new(
      encoding::BytesEncoder::without_length_prefix(self.hash.as_bytes()),
      encoding::ArrayEncoder::without_length_prefix(self.index.to_le_bytes()),
    ))
  }
}

/// Decoder for [`OutPoint`].
#[derive(Clone, Debug)]
pub struct OutPointDecoder(encoding::ArrayDecoder<36>);

impl OutPointDecoder {
  /// Constructs a new decoder.
  pub const fn new() -> Self {
    Self(encoding::ArrayDecoder::new())
  }
}

impl Default for OutPointDecoder {
  fn default() -> Self {
    Self::new()
  }
}

/// Decode error for [`OutPoint`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OutPointDecoderError(encoding::UnexpectedEofError);

impl fmt::Display for OutPointDecoderError {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "outpoint decode failed: {}", self.0)
  }
}

impl encoding::Decoder for OutPointDecoder {
  type Output = OutPoint;
  type Error = OutPointDecoderError;

  #[inline]
  fn push_bytes(&mut self, bytes: &mut &[u8]) -> Result<bool, Self::Error> {
    self.0.push_bytes(bytes).map_err(OutPointDecoderError)
  }

  #[inline]
  fn end(self) -> Result<Self::Output, Self::Error> {
    let encoded = self.0.end().map_err(OutPointDecoderError)?;
    let (hash_buf, index_buf) = encoded.split_array::<32, 4>();
    Ok(OutPoint {
      hash: TxHash::from_bytes(*hash_buf),
      index: u32::from_le_bytes(*index_buf),
    })
  }

  #[inline]
  fn read_limit(&self) -> usize {
    self.0.read_limit()
  }
}

impl encoding::Decodable for OutPoint {
  type Decoder = OutPointDecoder;
  fn decoder() -> Self::Decoder {
    OutPointDecoder::new()
  }
}
