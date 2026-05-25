//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Inventory messages: inv, getdata, notfound.

use crate::encode::MAX_P2P_PAYLOAD;
use crate::prelude::*;
use crate::primitives::inventory::{InvType, Inventory};

use bitcoin_consensus_encoding as encoding;
use dash_num::Hash256;
use dash_types::codec::{self, Codec, DecodeError, NumCodec};
use dash_types::{BufferDecoder, VecEncoder};

/// Maximum inventory items per message.
const MAX_INV_ITEMS: usize = 50_000;

/// Helper: decode a CompactSize-prefixed vector of inventory items.
fn decode_inv_list(data: &mut &[u8]) -> Result<Vec<Inventory>, DecodeError> {
  let count = codec::read_compact_size(data, MAX_INV_ITEMS)?;
  let mut items = Vec::with_capacity(count);
  for _ in 0..count {
    let raw_type = codec::read_u32_le(data)?;
    let hash = Hash256::decode(data)?;
    items.push(Inventory {
      inv_type: InvType::from_base(raw_type),
      hash,
    });
  }
  Ok(items)
}

/// Helper: encode a CompactSize-prefixed vector of inventory items.
fn encode_inv_list(items: &[Inventory], buf: &mut Vec<u8>) {
  codec::write_compact_size(items.len(), buf);
  for item in items {
    buf.extend_from_slice(&item.inv_type.to_base().to_le_bytes());
    buf.extend_from_slice(&item.hash.to_bytes());
  }
}

/// Announces available inventory to a peer.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct Inv {
  /// Inventory items being announced.
  pub inventory: Vec<Inventory>,
}

impl Inv {
  fn decode(data: &mut &[u8]) -> Result<Self, DecodeError> {
    decode_inv_list(data).map(|inventory| Self { inventory })
  }
}

impl encoding::Encodable for Inv {
  type Encoder<'e> = VecEncoder;
  fn encoder(&self) -> Self::Encoder<'_> {
    let mut buf = Vec::new();
    encode_inv_list(&self.inventory, &mut buf);
    VecEncoder::new(buf)
  }
}

impl encoding::Decodable for Inv {
  type Decoder = BufferDecoder<Inv, DecodeError>;
  fn decoder() -> Self::Decoder {
    BufferDecoder::new(Inv::decode, MAX_P2P_PAYLOAD)
  }
}

/// Requests specific inventory items from a peer.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct GetData {
  /// Inventory items being requested.
  pub inventory: Vec<Inventory>,
}

impl GetData {
  fn decode(data: &mut &[u8]) -> Result<Self, DecodeError> {
    decode_inv_list(data).map(|inventory| Self { inventory })
  }
}

impl encoding::Encodable for GetData {
  type Encoder<'e> = VecEncoder;
  fn encoder(&self) -> Self::Encoder<'_> {
    let mut buf = Vec::new();
    encode_inv_list(&self.inventory, &mut buf);
    VecEncoder::new(buf)
  }
}

impl encoding::Decodable for GetData {
  type Decoder = BufferDecoder<GetData, DecodeError>;
  fn decoder() -> Self::Decoder {
    BufferDecoder::new(GetData::decode, MAX_P2P_PAYLOAD)
  }
}

/// Indicates requested inventory items were not found.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct NotFound {
  /// Missing inventory items.
  pub inventory: Vec<Inventory>,
}

impl NotFound {
  fn decode(data: &mut &[u8]) -> Result<Self, DecodeError> {
    decode_inv_list(data).map(|inventory| Self { inventory })
  }
}

impl encoding::Encodable for NotFound {
  type Encoder<'e> = VecEncoder;
  fn encoder(&self) -> Self::Encoder<'_> {
    let mut buf = Vec::new();
    encode_inv_list(&self.inventory, &mut buf);
    VecEncoder::new(buf)
  }
}

impl encoding::Decodable for NotFound {
  type Decoder = BufferDecoder<NotFound, DecodeError>;
  fn decoder() -> Self::Decoder {
    BufferDecoder::new(NotFound::decode, MAX_P2P_PAYLOAD)
  }
}
