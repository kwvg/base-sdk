//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Governance object message.

use crate::prelude::*;
use crate::primitives::governance::GovernanceObject;

use dash_types::codec::{Codec, DecodeError};

/// A governance object broadcast or response.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct GovObj {
  /// The governance object.
  pub object: GovernanceObject,
}

impl Codec for GovObj {
  fn decode(data: &mut &[u8]) -> Result<Self, DecodeError> {
    let object = GovernanceObject::decode(data)?;
    Ok(Self { object })
  }

  fn encode(&self, buf: &mut Vec<u8>) {
    self.object.encode(buf);
  }
}

crate::codec::impl_p2p!(GovObj);
