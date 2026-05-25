//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Inventory messages: inv, getdata, notfound.

use crate::prelude::*;
use crate::primitives::inventory::Inventory;

use dash_types::codec::{self, Codec, DecodeError};

/// Maximum inventory items per message.
const MAX_INV_ITEMS: usize = 50_000;

/// Announces available inventory to a peer.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct Inv {
  /// Inventory items being announced.
  pub inventory: Vec<Inventory>,
}

impl Codec for Inv {
  fn decode(data: &mut &[u8]) -> Result<Self, DecodeError> {
    Ok(Self { inventory: codec::read_vec(data, MAX_INV_ITEMS)? })
  }

  fn encode(&self, buf: &mut Vec<u8>) {
    codec::write_vec(&self.inventory, buf);
  }
}

crate::codec::impl_p2p!(Inv);

/// Requests specific inventory items from a peer.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct GetData {
  /// Inventory items being requested.
  pub inventory: Vec<Inventory>,
}

impl Codec for GetData {
  fn decode(data: &mut &[u8]) -> Result<Self, DecodeError> {
    Ok(Self { inventory: codec::read_vec(data, MAX_INV_ITEMS)? })
  }

  fn encode(&self, buf: &mut Vec<u8>) {
    codec::write_vec(&self.inventory, buf);
  }
}

crate::codec::impl_p2p!(GetData);

/// Indicates requested inventory items were not found.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct NotFound {
  /// Missing inventory items.
  pub inventory: Vec<Inventory>,
}

impl Codec for NotFound {
  fn decode(data: &mut &[u8]) -> Result<Self, DecodeError> {
    Ok(Self { inventory: codec::read_vec(data, MAX_INV_ITEMS)? })
  }

  fn encode(&self, buf: &mut Vec<u8>) {
    codec::write_vec(&self.inventory, buf);
  }
}

crate::codec::impl_p2p!(NotFound);
