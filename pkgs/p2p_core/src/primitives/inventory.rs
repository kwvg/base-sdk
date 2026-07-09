//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Inventory vector used by inv, getdata, and notfound messages.

use crate::codec::codec_p2p;

use dash_num::Hash256;
use dash_primitives::hash_impl;
use dash_types::{enum_map, impl_num, TypeId};

use core::fmt;

enum_map! {
/// Inventory object type.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, TypeId)]
pub enum InvType, u32, Unknown {
  /// Error / not used.
  Error = 0 => "error",
  /// Transaction.
  Tx = 1 => "tx",
  /// Block.
  Block = 2 => "block",
  /// Filtered block (BIP37).
  FilteredBlock = 3 => "filtered_block",
  /// Compact block (BIP152).
  CompactBlock = 4 => "compact_block",
  /// Governance object.
  GovernanceObject = 17 => "governance_object",
  /// Governance object vote.
  GovernanceObjectVote = 18 => "governance_object_vote",
}
}

impl_num!(InvType, u32);

hash_impl!(InvType);

/// An inventory vector: a typed 32-byte hash.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct Inventory {
  /// Object type.
  #[cfg_attr(feature = "serde", serde(rename = "type"))]
  pub inv_type: InvType,
  /// Object hash.
  pub hash: Hash256,
}

codec_p2p!(Inventory { inv_type, hash });

impl fmt::Display for Inventory {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "{}:{}", self.inv_type, self.hash)
  }
}
