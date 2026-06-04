//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Governance object and vote types.

use crate::encode::{encode_compact_size, BufferDecoder, VecEncoder, WireDecodeError, MAX_P2P_PAYLOAD};
use crate::prelude::*;

use bitcoin_consensus_encoding as encoding;
use dash_num::Hash256;
use dash_primitives::wire;
use dash_primitives::OutPoint;
use dash_types::BlsSignatureBytes;

use core::fmt;

/// Governance vote outcome.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
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

impl VoteOutcome {
  /// Converts from the on-wire `u32`.
  pub const fn from_u32(v: u32) -> Self {
    match v {
      0 => Self::None,
      1 => Self::Yes,
      2 => Self::No,
      3 => Self::Abstain,
      other => Self::Unknown(other),
    }
  }

  /// Returns the on-wire `u32`.
  pub const fn to_u32(self) -> u32 {
    match self {
      Self::None => 0,
      Self::Yes => 1,
      Self::No => 2,
      Self::Abstain => 3,
      Self::Unknown(v) => v,
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

#[cfg(feature = "serde")]
impl dash_types::AsUint<u32> for VoteOutcome {
  fn as_uint(&self) -> u32 {
    self.to_u32()
  }
}

#[cfg(feature = "serde")]
impl dash_types::TryFromUint<u32> for VoteOutcome {
  type Err = core::convert::Infallible;

  fn try_from_uint(v: u32) -> Result<Self, Self::Err> {
    Ok(Self::from_u32(v))
  }
}

/// Governance vote signal type.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
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

impl VoteSignal {
  /// Converts from the on-wire `u32`.
  pub const fn from_u32(v: u32) -> Self {
    match v {
      0 => Self::None,
      1 => Self::Funding,
      2 => Self::Valid,
      3 => Self::Delete,
      4 => Self::Endorsed,
      other => Self::Unknown(other),
    }
  }

  /// Returns the on-wire `u32`.
  pub const fn to_u32(self) -> u32 {
    match self {
      Self::None => 0,
      Self::Funding => 1,
      Self::Valid => 2,
      Self::Delete => 3,
      Self::Endorsed => 4,
      Self::Unknown(v) => v,
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

#[cfg(feature = "serde")]
impl dash_types::AsUint<u32> for VoteSignal {
  fn as_uint(&self) -> u32 {
    self.to_u32()
  }
}

#[cfg(feature = "serde")]
impl dash_types::TryFromUint<u32> for VoteSignal {
  type Err = core::convert::Infallible;

  fn try_from_uint(v: u32) -> Result<Self, Self::Err> {
    Ok(Self::from_u32(v))
  }
}

/// A governance object (proposal or superblock trigger).
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
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

impl GovernanceObject {
  pub(crate) fn decode_from_slice(data: &[u8]) -> Result<Self, WireDecodeError> {
    let sl = &mut &data[..];
    let parent_hash = wire::read_hash(sl)?;
    let revision = wire::read_u32_le(sl)?;
    let time = wire::read_i64_le(sl)?;
    let collateral_hash = wire::read_hash(sl)?;
    let outpoint_hash: dash_primitives::TxHash = wire::read_hash(sl)?.into();
    let outpoint_n = wire::read_u32_le(sl)?;
    let mn_outpoint = OutPoint {
      hash: outpoint_hash,
      index: outpoint_n,
    };
    let data_len = wire::read_compact_size(sl, MAX_P2P_PAYLOAD)?;
    let obj_data = wire::read_bytes(sl, data_len)?.to_vec();
    let sig = BlsSignatureBytes(wire::read_array(sl)?);
    Ok(Self {
      parent_hash,
      revision,
      time,
      collateral_hash,
      mn_outpoint,
      data: obj_data,
      sig,
    })
  }

  pub(crate) fn encode_to_vec_buf(&self) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(&self.parent_hash.to_bytes());
    buf.extend_from_slice(&self.revision.to_le_bytes());
    buf.extend_from_slice(&self.time.to_le_bytes());
    buf.extend_from_slice(&self.collateral_hash.to_bytes());
    buf.extend_from_slice(&self.mn_outpoint.hash.to_bytes());
    buf.extend_from_slice(&self.mn_outpoint.index.to_le_bytes());
    encode_compact_size(self.data.len(), &mut buf);
    buf.extend_from_slice(&self.data);
    buf.extend_from_slice(&self.sig.0);
    buf
  }
}

impl encoding::Encodable for GovernanceObject {
  type Encoder<'e> = VecEncoder;
  fn encoder(&self) -> Self::Encoder<'_> {
    VecEncoder::new(self.encode_to_vec_buf())
  }
}

impl encoding::Decodable for GovernanceObject {
  type Decoder = BufferDecoder<GovernanceObject, WireDecodeError>;
  fn decoder() -> Self::Decoder {
    BufferDecoder::new(GovernanceObject::decode_from_slice, MAX_P2P_PAYLOAD)
  }
}

/// A masternode vote on a governance object.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct GovernanceVote {
  /// Masternode outpoint casting the vote.
  pub mn_outpoint: OutPoint,
  /// Hash of the governance object being voted on.
  pub parent_hash: Hash256,
  /// Vote outcome.
  #[cfg_attr(feature = "serde", serde(with = "dash_types::serialize::uint::w32"))]
  pub outcome: VoteOutcome,
  /// Vote signal type.
  #[cfg_attr(feature = "serde", serde(with = "dash_types::serialize::uint::w32"))]
  pub signal: VoteSignal,
  /// Vote timestamp (seconds since epoch).
  pub time: i64,
  /// BLS signature.
  pub sig: BlsSignatureBytes,
}

impl GovernanceVote {
  pub(crate) fn decode_from_slice(data: &[u8]) -> Result<Self, WireDecodeError> {
    let sl = &mut &data[..];
    let outpoint_hash: dash_primitives::TxHash = wire::read_hash(sl)?.into();
    let outpoint_n = wire::read_u32_le(sl)?;
    let mn_outpoint = OutPoint {
      hash: outpoint_hash,
      index: outpoint_n,
    };
    let parent_hash = wire::read_hash(sl)?;
    let outcome = VoteOutcome::from_u32(wire::read_u32_le(sl)?);
    let signal = VoteSignal::from_u32(wire::read_u32_le(sl)?);
    let time = wire::read_i64_le(sl)?;
    let sig = BlsSignatureBytes(wire::read_array(sl)?);
    Ok(Self {
      mn_outpoint,
      parent_hash,
      outcome,
      signal,
      time,
      sig,
    })
  }

  pub(crate) fn encode_to_vec(&self) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(&self.mn_outpoint.hash.to_bytes());
    buf.extend_from_slice(&self.mn_outpoint.index.to_le_bytes());
    buf.extend_from_slice(&self.parent_hash.to_bytes());
    buf.extend_from_slice(&self.outcome.to_u32().to_le_bytes());
    buf.extend_from_slice(&self.signal.to_u32().to_le_bytes());
    buf.extend_from_slice(&self.time.to_le_bytes());
    buf.extend_from_slice(&self.sig.0);
    buf
  }
}

impl encoding::Encodable for GovernanceVote {
  type Encoder<'e> = VecEncoder;
  fn encoder(&self) -> Self::Encoder<'_> {
    VecEncoder::new(self.encode_to_vec())
  }
}

impl encoding::Decodable for GovernanceVote {
  type Decoder = BufferDecoder<GovernanceVote, WireDecodeError>;
  fn decoder() -> Self::Decoder {
    BufferDecoder::new(GovernanceVote::decode_from_slice, MAX_P2P_PAYLOAD)
  }
}
