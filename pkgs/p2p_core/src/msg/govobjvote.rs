//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Governance vote message.

use crate::prelude::*;
use crate::primitives::governance::GovernanceVote;

use dash_types::codec::{Codec, DecodeError};

/// A masternode vote on a governance object.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct GovObjVote {
  /// The vote.
  pub vote: GovernanceVote,
}

impl Codec for GovObjVote {
  fn decode(data: &mut &[u8]) -> Result<Self, DecodeError> {
    let vote = GovernanceVote::decode(data)?;
    Ok(Self { vote })
  }

  fn encode(&self, buf: &mut Vec<u8>) {
    self.vote.encode(buf);
  }
}

crate::codec::impl_p2p!(GovObjVote);
