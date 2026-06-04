//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Dash block header (80 bytes).

use crate::{BlockHash, MerkleRoot};

use bitcoin_consensus_encoding as encoding;
use bitcoin_internals::array::ArrayExt as _;

use core::fmt;

/// A Dash block header (80 bytes on the wire).
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct BlockHeader {
  /// Block version.
  pub version: i32,
  /// Hash of the previous block header.
  pub prev_hash: BlockHash,
  /// Merkle root of the transaction tree.
  pub merkle_root: MerkleRoot,
  /// Block timestamp (unix epoch seconds).
  pub time: u32,
  /// Compact difficulty target (nBits).
  pub bits: u32,
  /// Nonce used for proof-of-work.
  pub nonce: u32,
}

impl fmt::Display for BlockHeader {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(
      f,
      "BlockHeader {{ version: {}, prev_hash: {}, time: {} }}",
      self.version, self.prev_hash, self.time,
    )
  }
}

// Ecosystem encoding traits.

type BlockHeaderEncoderInner<'e> = encoding::Encoder6<
  encoding::ArrayEncoder<4>,
  encoding::BytesEncoder<'e>,
  encoding::BytesEncoder<'e>,
  encoding::ArrayEncoder<4>,
  encoding::ArrayEncoder<4>,
  encoding::ArrayEncoder<4>,
>;

encoding::encoder_newtype! {
  /// Encoder for [`BlockHeader`].
  pub struct BlockHeaderEncoder<'e>(BlockHeaderEncoderInner<'e>);
}

impl encoding::Encodable for BlockHeader {
  type Encoder<'e> = BlockHeaderEncoder<'e>;

  fn encoder(&self) -> Self::Encoder<'_> {
    BlockHeaderEncoder::new(encoding::Encoder6::new(
      encoding::ArrayEncoder::without_length_prefix(self.version.to_le_bytes()),
      encoding::BytesEncoder::without_length_prefix(self.prev_hash.as_bytes()),
      encoding::BytesEncoder::without_length_prefix(self.merkle_root.as_bytes()),
      encoding::ArrayEncoder::without_length_prefix(self.time.to_le_bytes()),
      encoding::ArrayEncoder::without_length_prefix(self.bits.to_le_bytes()),
      encoding::ArrayEncoder::without_length_prefix(self.nonce.to_le_bytes()),
    ))
  }
}

/// Decoder for [`BlockHeader`].
#[derive(Clone, Debug)]
pub struct BlockHeaderDecoder(encoding::ArrayDecoder<80>);

impl BlockHeaderDecoder {
  /// Constructs a new decoder.
  pub const fn new() -> Self {
    Self(encoding::ArrayDecoder::new())
  }
}

impl Default for BlockHeaderDecoder {
  fn default() -> Self {
    Self::new()
  }
}

/// Decode error for [`BlockHeader`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlockHeaderDecoderError(encoding::UnexpectedEofError);

impl fmt::Display for BlockHeaderDecoderError {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "block header decode: {}", self.0)
  }
}

impl encoding::Decoder for BlockHeaderDecoder {
  type Output = BlockHeader;
  type Error = BlockHeaderDecoderError;

  #[inline]
  fn push_bytes(&mut self, bytes: &mut &[u8]) -> Result<bool, Self::Error> {
    self.0.push_bytes(bytes).map_err(BlockHeaderDecoderError)
  }

  #[inline]
  fn end(self) -> Result<Self::Output, Self::Error> {
    let buf = self.0.end().map_err(BlockHeaderDecoderError)?;
    let (version_buf, rest) = buf.split_array::<4, 76>();
    let (prev_hash_buf, rest) = rest.split_array::<32, 44>();
    let (merkle_buf, rest) = rest.split_array::<32, 12>();
    let (time_buf, rest) = rest.split_array::<4, 8>();
    let (bits_buf, nonce_buf) = rest.split_array::<4, 4>();

    Ok(BlockHeader {
      version: i32::from_le_bytes(*version_buf),
      prev_hash: BlockHash::from_bytes(*prev_hash_buf),
      merkle_root: MerkleRoot::from_bytes(*merkle_buf),
      time: u32::from_le_bytes(*time_buf),
      bits: u32::from_le_bytes(*bits_buf),
      nonce: u32::from_le_bytes(*nonce_buf),
    })
  }

  #[inline]
  fn read_limit(&self) -> usize {
    self.0.read_limit()
  }
}

impl encoding::Decodable for BlockHeader {
  type Decoder = BlockHeaderDecoder;
  fn decoder() -> Self::Decoder {
    BlockHeaderDecoder::new()
  }
}
