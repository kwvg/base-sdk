//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Inventory messages: inv, getdata, notfound.

use crate::encode::MAX_P2P_PAYLOAD;
use crate::error::P2pDecodeError;
use crate::prelude::*;
use crate::primitives::inventory::{InvType, Inventory};

use bitcoin_consensus_encoding as encoding;
use dash_num::Hash256;
use dash_primitives::codec::{BufferDecoder, VecEncoder};
use dash_types::codec;

/// Maximum inventory items per message.
const MAX_INV_ITEMS: usize = 50_000;

/// Helper: decode a CompactSize-prefixed vector of inventory items.
fn decode_inv_list(sl: &mut &[u8]) -> Result<Vec<Inventory>, P2pDecodeError> {
  let count = codec::read_compact_size(sl, MAX_INV_ITEMS)?;
  let mut items = Vec::with_capacity(count);
  for _ in 0..count {
    let raw_type = codec::read_u32_le(sl)?;
    let hash = Hash256::from_bytes(codec::take(sl)?);
    items.push(Inventory {
      inv_type: InvType::from_u32(raw_type),
      hash,
    });
  }
  Ok(items)
}

/// Helper: encode a CompactSize-prefixed vector of inventory items.
fn encode_inv_list(items: &[Inventory], buf: &mut Vec<u8>) {
  codec::write_compact_size(items.len(), buf);
  for item in items {
    buf.extend_from_slice(&item.inv_type.to_u32().to_le_bytes());
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
  fn decode_from_slice(data: &[u8]) -> Result<Self, P2pDecodeError> {
    let sl = &mut &data[..];
    decode_inv_list(sl).map(|inventory| Self { inventory })
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
  type Decoder = BufferDecoder<Inv, P2pDecodeError>;
  fn decoder() -> Self::Decoder {
    BufferDecoder::new(Inv::decode_from_slice, MAX_P2P_PAYLOAD)
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
  fn decode_from_slice(data: &[u8]) -> Result<Self, P2pDecodeError> {
    let sl = &mut &data[..];
    decode_inv_list(sl).map(|inventory| Self { inventory })
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
  type Decoder = BufferDecoder<GetData, P2pDecodeError>;
  fn decoder() -> Self::Decoder {
    BufferDecoder::new(GetData::decode_from_slice, MAX_P2P_PAYLOAD)
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
  fn decode_from_slice(data: &[u8]) -> Result<Self, P2pDecodeError> {
    let sl = &mut &data[..];
    decode_inv_list(sl).map(|inventory| Self { inventory })
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
  type Decoder = BufferDecoder<NotFound, P2pDecodeError>;
  fn decoder() -> Self::Decoder {
    BufferDecoder::new(NotFound::decode_from_slice, MAX_P2P_PAYLOAD)
  }
}
