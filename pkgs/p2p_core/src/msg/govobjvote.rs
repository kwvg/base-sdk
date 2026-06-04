//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Governance vote message.

use crate::encode::{BufferDecoder, VecEncoder, WireDecodeError, MAX_P2P_PAYLOAD};
use crate::primitives::governance::GovernanceVote;

use bitcoin_consensus_encoding as encoding;

/// A masternode vote on a governance object.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct GovObjVote {
  /// The vote.
  pub vote: GovernanceVote,
}

impl GovObjVote {
  fn decode_from_slice(data: &[u8]) -> Result<Self, WireDecodeError> {
    let vote = GovernanceVote::decode_from_slice(data)?;
    Ok(Self { vote })
  }
}

impl encoding::Encodable for GovObjVote {
  type Encoder<'e> = VecEncoder;
  fn encoder(&self) -> Self::Encoder<'_> {
    VecEncoder::new(self.vote.encode_to_vec())
  }
}

impl encoding::Decodable for GovObjVote {
  type Decoder = BufferDecoder<GovObjVote, WireDecodeError>;
  fn decoder() -> Self::Decoder {
    BufferDecoder::new(GovObjVote::decode_from_slice, MAX_P2P_PAYLOAD)
  }
}
