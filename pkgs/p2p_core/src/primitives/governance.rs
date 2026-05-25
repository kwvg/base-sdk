//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Governance object and vote types.

use crate::prelude::*;

use dash_num::Hash256;
use dash_primitives::OutPoint;
use dash_types::codec::{Codec, DecodeError, NumCodec};
use dash_types::BlsSignatureBytes;

use core::fmt;

/// Governance vote outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum VoteOutcome {
  /// No vote cast.
  None,
  /// Vote in favour.
  Yes,
  /// Vote against.
  No,
  /// Abstention.
  Abstain,
  /// Unrecognised outcome.
  Unknown(u32),
}

impl NumCodec<u32> for VoteOutcome {
  fn from_base(v: u32) -> Self {
    match v {
      0 => Self::None,
      1 => Self::Yes,
      2 => Self::No,
      3 => Self::Abstain,
      other => Self::Unknown(other),
    }
  }

  fn to_base(&self) -> u32 {
    match self {
      Self::None => 0,
      Self::Yes => 1,
      Self::No => 2,
      Self::Abstain => 3,
      Self::Unknown(v) => *v,
    }
  }
}

impl fmt::Display for VoteOutcome {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    match self {
      Self::None => f.write_str("none"),
      Self::Yes => f.write_str("yes"),
      Self::No => f.write_str("no"),
      Self::Abstain => f.write_str("abstain"),
      Self::Unknown(v) => write!(f, "unknown({v})"),
    }
  }
}

dash_types::impl_num!(VoteOutcome, u32);

/// Governance vote signal type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum VoteSignal {
  /// No signal.
  None,
  /// Fund this object.
  Funding,
  /// Object checks out.
  Valid,
  /// Object should be deleted.
  Delete,
  /// Officially endorsed.
  Endorsed,
  /// Unrecognised signal.
  Unknown(u32),
}

impl NumCodec<u32> for VoteSignal {
  fn from_base(v: u32) -> Self {
    match v {
      0 => Self::None,
      1 => Self::Funding,
      2 => Self::Valid,
      3 => Self::Delete,
      4 => Self::Endorsed,
      other => Self::Unknown(other),
    }
  }

  fn to_base(&self) -> u32 {
    match self {
      Self::None => 0,
      Self::Funding => 1,
      Self::Valid => 2,
      Self::Delete => 3,
      Self::Endorsed => 4,
      Self::Unknown(v) => *v,
    }
  }
}

impl fmt::Display for VoteSignal {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    match self {
      Self::None => f.write_str("none"),
      Self::Funding => f.write_str("funding"),
      Self::Valid => f.write_str("valid"),
      Self::Delete => f.write_str("delete"),
      Self::Endorsed => f.write_str("endorsed"),
      Self::Unknown(v) => write!(f, "unknown({v})"),
    }
  }
}

dash_types::impl_num!(VoteSignal, u32);

/// A governance object (proposal or superblock trigger).
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct GovernanceObject {
  /// Parent object hash (zero for root objects).
  pub parent_hash: Hash256,
  /// Revision number.
  pub revision: u32,
  /// Creation timestamp (seconds since epoch).
  pub time: i64,
  /// Fee transaction hash.
  pub collateral_hash: Hash256,
  /// Masternode outpoint that signed this object.
  pub mn_outpoint: OutPoint,
  /// Serialised JSON data.
  #[cfg_attr(feature = "serde", serde(with = "dash_types::serialize::hex"))]
  pub data: Vec<u8>,
  /// BLS signature.
  pub sig: BlsSignatureBytes,
}

impl Codec for GovernanceObject {
  fn decode(data: &mut &[u8]) -> Result<Self, DecodeError> {
    Ok(Self {
      parent_hash: Hash256::decode(data)?,
      revision: u32::decode(data)?,
      time: i64::decode(data)?,
      collateral_hash: Hash256::decode(data)?,
      mn_outpoint: OutPoint::decode(data)?,
      data: Vec::decode(data)?,
      sig: BlsSignatureBytes::decode(data)?,
    })
  }

  fn encode(&self, buf: &mut Vec<u8>) {
    self.parent_hash.encode(buf);
    self.revision.encode(buf);
    self.time.encode(buf);
    self.collateral_hash.encode(buf);
    self.mn_outpoint.encode(buf);
    self.data.encode(buf);
    self.sig.encode(buf);
  }
}

crate::codec::impl_p2p!(GovernanceObject);

/// A masternode vote on a governance object.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct GovernanceVote {
  /// Masternode outpoint casting the vote.
  pub mn_outpoint: OutPoint,
  /// Hash of the governance object being voted on.
  pub parent_hash: Hash256,
  /// Vote outcome.
  pub outcome: VoteOutcome,
  /// Vote signal type.
  pub signal: VoteSignal,
  /// Vote timestamp (seconds since epoch).
  pub time: i64,
  /// BLS signature.
  pub sig: BlsSignatureBytes,
}

impl Codec for GovernanceVote {
  fn decode(data: &mut &[u8]) -> Result<Self, DecodeError> {
    Ok(Self {
      mn_outpoint: OutPoint::decode(data)?,
      parent_hash: Hash256::decode(data)?,
      outcome: VoteOutcome::from_base(u32::decode(data)?),
      signal: VoteSignal::from_base(u32::decode(data)?),
      time: i64::decode(data)?,
      sig: BlsSignatureBytes::decode(data)?,
    })
  }

  fn encode(&self, buf: &mut Vec<u8>) {
    self.mn_outpoint.encode(buf);
    self.parent_hash.encode(buf);
    self.outcome.to_base().encode(buf);
    self.signal.to_base().encode(buf);
    self.time.encode(buf);
    self.sig.encode(buf);
  }
}

crate::codec::impl_p2p!(GovernanceVote);
