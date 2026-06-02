//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Governance object message.

use crate::encode::{BufferDecoder, VecEncoder, WireDecodeError, MAX_P2P_PAYLOAD};
use crate::primitives::governance::GovernanceObject;

use bitcoin_consensus_encoding as encoding;

/// A governance object broadcast or response.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct GovObj {
  /// The governance object.
  pub object: GovernanceObject,
}

impl GovObj {
  fn decode_from_slice(data: &[u8]) -> Result<Self, WireDecodeError> {
    let object = GovernanceObject::decode_from_slice(data)?;
    Ok(Self { object })
  }
}

impl encoding::Encodable for GovObj {
  type Encoder<'e> = VecEncoder;
  fn encoder(&self) -> Self::Encoder<'_> {
    VecEncoder::new(self.object.encode_to_vec_buf())
  }
}

impl encoding::Decodable for GovObj {
  type Decoder = BufferDecoder<GovObj, WireDecodeError>;
  fn decoder() -> Self::Decoder {
    BufferDecoder::new(GovObj::decode_from_slice, MAX_P2P_PAYLOAD)
  }
}
