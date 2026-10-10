//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Inventory messages and types.

use crate::codec::codec_p2p;
use crate::error::{check_count, TooManyEntries};
use crate::prelude::*;

use dash_num::Hash256;
use dash_primitives::hash_impl;
use dash_types::type_id::TypeId;
use dash_types::{enum_map, impl_num, Checkable};

use core::fmt;

/// Largest number of entries in an `inv` or `getdata` message.
const MAX_INV_SZ: usize = 50_000;

/// Requests specific inventory items from a peer.
#[derive(Clone, Debug, Eq, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct GetData {
  /// Inventory items being requested.
  pub inventory: Vec<Inventory>,
}

codec_p2p!(GetData { inventory });

impl Checkable for GetData {
  type Error = TooManyEntries;

  fn check(&self) -> Option<Self::Error> {
    check_count(self.inventory.len(), MAX_INV_SZ)
  }
}

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
    /// Spork message.
    Spork = 6 => "spork",
    /// CoinJoin broadcast transaction.
    Dstx = 16 => "dstx",
    /// Governance object.
    GovernanceObject = 17 => "governance_object",
    /// Governance object vote.
    GovernanceObjectVote = 18 => "governance_object_vote",
    /// Compact block (BIP152).
    CompactBlock = 20 => "compact_block",
    /// LLMQ final commitment.
    QuorumFinalCommitment = 21 => "quorum_final_commitment",
    /// LLMQ DKG contribution.
    QuorumContrib = 23 => "quorum_contrib",
    /// LLMQ DKG complaint.
    QuorumComplaint = 24 => "quorum_complaint",
    /// LLMQ DKG justification.
    QuorumJustification = 25 => "quorum_justification",
    /// LLMQ DKG premature commitment.
    QuorumPrematureCommitment = 26 => "quorum_premature_commitment",
    /// LLMQ recovered signature.
    QuorumRecoveredSig = 28 => "quorum_recovered_sig",
    /// ChainLock signature.
    ClSig = 29 => "clsig",
    /// Deterministic InstantSend lock.
    IsdLock = 31 => "isdlock",
    /// CoinJoin queue announcement.
    Dsq = 32 => "dsq",
    /// Platform service ban (DIP-0031).
    PlatformBan = 33 => "platform_ban",
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

/// Announces available inventory to a peer.
#[derive(Clone, Debug, Eq, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct Inv {
  /// Inventory items being announced.
  pub inventory: Vec<Inventory>,
}

codec_p2p!(Inv { inventory });

impl Checkable for Inv {
  type Error = TooManyEntries;

  fn check(&self) -> Option<Self::Error> {
    check_count(self.inventory.len(), MAX_INV_SZ)
  }
}

/// Indicates requested inventory items were not found.
#[derive(Clone, Debug, Eq, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct NotFound {
  /// Missing inventory items.
  pub inventory: Vec<Inventory>,
}

codec_p2p!(NotFound { inventory });

#[cfg(all(test, feature = "serde"))]
mod tests {
  use super::*;

  use dash_dev::{assert_serde_rt, check_wire, Corpus};
  use dash_types::Numeric;
  use rstest::rstest;

  #[rstest]
  #[case::spork(6, InvType::Spork)]
  #[case::dstx(16, InvType::Dstx)]
  #[case::quorum_final_commitment(21, InvType::QuorumFinalCommitment)]
  #[case::quorum_contrib(23, InvType::QuorumContrib)]
  #[case::quorum_complaint(24, InvType::QuorumComplaint)]
  #[case::quorum_justification(25, InvType::QuorumJustification)]
  #[case::quorum_premature_commitment(26, InvType::QuorumPrematureCommitment)]
  #[case::quorum_recovered_sig(28, InvType::QuorumRecoveredSig)]
  #[case::clsig(29, InvType::ClSig)]
  #[case::isdlock(31, InvType::IsdLock)]
  #[case::dsq(32, InvType::Dsq)]
  #[case::platform_ban(33, InvType::PlatformBan)]
  fn inv_types_follow_the_reference_codes(#[case] code: u32, #[case] inv_type: InvType) {
    assert_eq!(InvType::from_base(code), inv_type);
    assert_eq!(inv_type.to_base(), code);
  }

  #[rstest]
  #[case::legacy_txlock_request(4)]
  #[case::masternode_verify(19)]
  #[case::quorum_dummy_commitment(22)]
  #[case::quorum_debug_status(27)]
  #[case::islock(30)]
  #[case::asset_unlock(34)]
  fn other_inv_codes_are_unknown(#[case] code: u32) {
    assert_eq!(InvType::from_base(code), InvType::Unknown(code));
  }

  fn inventory(count: usize) -> Vec<Inventory> {
    vec![
      Inventory {
        inv_type: InvType::Tx,
        hash: Hash256::default(),
      };
      count
    ]
  }

  #[rstest]
  #[case::empty(0, None)]
  #[case::at_limit(MAX_INV_SZ, None)]
  #[case::past_limit(MAX_INV_SZ + 1, Some(TooManyEntries { count: MAX_INV_SZ + 1, limit: MAX_INV_SZ }))]
  fn inv_and_getdata_carry_at_most_50000_entries(#[case] count: usize, #[case] expected: Option<TooManyEntries>) {
    assert_eq!(
      Inv {
        inventory: inventory(count)
      }
      .check(),
      expected
    );
    assert_eq!(
      GetData {
        inventory: inventory(count)
      }
      .check(),
      expected
    );
  }

  #[rstest]
  fn corpus_inv() {
    let corpus = Corpus::open(env!("CARGO_MANIFEST_DIR"), "inv");
    let items = corpus.entries::<Inv>("inv", check_wire);
    assert_serde_rt("inv", &items);
  }
}
