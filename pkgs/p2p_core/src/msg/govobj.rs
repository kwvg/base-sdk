//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Governance object message.

use crate::encode::MAX_P2P_PAYLOAD;
use crate::prelude::*;
use crate::primitives::governance::GovernanceObject;

use bitcoin_consensus_encoding as encoding;
use dash_types::codec::{Codec, DecodeError};
use dash_types::{BufferDecoder, VecEncoder};

/// A governance object broadcast or response.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct GovObj {
  /// The governance object.
  pub object: GovernanceObject,
}

impl GovObj {
  fn decode(data: &mut &[u8]) -> Result<Self, DecodeError> {
    let object = <GovernanceObject as Codec>::decode(data)?;
    Ok(Self { object })
  }
}

impl encoding::Encodable for GovObj {
  type Encoder<'e> = VecEncoder;
  fn encoder(&self) -> Self::Encoder<'_> {
    let mut buf = Vec::new();
    Codec::encode(&self.object, &mut buf);
    VecEncoder::new(buf)
  }
}

impl encoding::Decodable for GovObj {
  type Decoder = BufferDecoder<GovObj, DecodeError>;
  fn decoder() -> Self::Decoder {
    BufferDecoder::new(GovObj::decode, MAX_P2P_PAYLOAD)
  }
}
