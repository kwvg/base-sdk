//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Masternode list diff messages: getmnlistd, mnlistdiff.

use crate::encode::{BufferDecoder, VecEncoder, WireDecodeError, MAX_P2P_PAYLOAD};
use crate::primitives::mn_list::MnListDiffPayload;

use bitcoin_consensus_encoding as encoding;
use dash_primitives::BlockHash;

use core::fmt;

/// Requests a masternode list diff between two blocks.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct GetMnListDiff {
  /// Base block hash (beginning of range).
  pub base_block_hash: BlockHash,
  /// Target block hash (end of range).
  pub block_hash: BlockHash,
}

type GetMnListDiffInnerEncoder = encoding::Encoder2<encoding::ArrayEncoder<32>, encoding::ArrayEncoder<32>>;

encoding::encoder_newtype_exact! {
  /// Encoder for [`GetMnListDiff`].
  pub struct GetMnListDiffEncoder<'e>(GetMnListDiffInnerEncoder);
}

impl encoding::Encodable for GetMnListDiff {
  type Encoder<'e> = GetMnListDiffEncoder<'e>;
  fn encoder(&self) -> Self::Encoder<'_> {
    GetMnListDiffEncoder::new(encoding::Encoder2::new(
      encoding::ArrayEncoder::without_length_prefix(self.base_block_hash.to_bytes()),
      encoding::ArrayEncoder::without_length_prefix(self.block_hash.to_bytes()),
    ))
  }
}

type GetMnListDiffInnerDecoder = encoding::Decoder2<encoding::ArrayDecoder<32>, encoding::ArrayDecoder<32>>;

/// Decoder for [`GetMnListDiff`].
#[derive(Clone, Debug)]
pub struct GetMnListDiffDecoder(GetMnListDiffInnerDecoder);

/// Decode error for [`GetMnListDiff`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GetMnListDiffDecoderError(<GetMnListDiffInnerDecoder as encoding::Decoder>::Error);

impl fmt::Display for GetMnListDiffDecoderError {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "getmnlistd decode: {}", self.0)
  }
}

impl encoding::Decoder for GetMnListDiffDecoder {
  type Output = GetMnListDiff;
  type Error = GetMnListDiffDecoderError;

  fn push_bytes(&mut self, bytes: &mut &[u8]) -> Result<bool, Self::Error> {
    self.0.push_bytes(bytes).map_err(GetMnListDiffDecoderError)
  }

  fn end(self) -> Result<Self::Output, Self::Error> {
    let (base, block) = self.0.end().map_err(GetMnListDiffDecoderError)?;
    Ok(GetMnListDiff {
      base_block_hash: BlockHash::from_bytes(base),
      block_hash: BlockHash::from_bytes(block),
    })
  }

  fn read_limit(&self) -> usize {
    self.0.read_limit()
  }
}

impl encoding::Decodable for GetMnListDiff {
  type Decoder = GetMnListDiffDecoder;
  fn decoder() -> Self::Decoder {
    GetMnListDiffDecoder(encoding::Decoder2::new(
      encoding::ArrayDecoder::<32>::new(),
      encoding::ArrayDecoder::<32>::new(),
    ))
  }
}

/// Response carrying the masternode list diff.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct MnListDiff {
  /// The full diff payload.
  pub payload: MnListDiffPayload,
}

impl MnListDiff {
  fn decode_from_slice(data: &[u8]) -> Result<Self, WireDecodeError> {
    MnListDiffPayload::decode_from_slice(data).map(|payload| Self { payload })
  }
}

impl encoding::Encodable for MnListDiff {
  type Encoder<'e> = VecEncoder;
  fn encoder(&self) -> Self::Encoder<'_> {
    VecEncoder::new(encoding::encode_to_vec(&self.payload))
  }
}

impl encoding::Decodable for MnListDiff {
  type Decoder = BufferDecoder<MnListDiff, WireDecodeError>;
  fn decoder() -> Self::Decoder {
    BufferDecoder::new(MnListDiff::decode_from_slice, MAX_P2P_PAYLOAD)
  }
}
