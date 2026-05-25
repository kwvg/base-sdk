//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! BIP157 compact filter checkpoint messages: getcfcheckpt, cfcheckpt.

use crate::prelude::*;
use crate::primitives::filter_type::FilterType;

use dash_primitives::BlockHash;
use dash_types::codec::{Codec, DecodeError};

/// Requests evenly-spaced compact filter checkpoints.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct GetCFCheckpt {
  /// Filter type.
  pub filter_type: FilterType,
  /// Stop block hash.
  pub stop_hash: BlockHash,
}

impl Codec for GetCFCheckpt {
  fn decode(data: &mut &[u8]) -> Result<Self, DecodeError> {
    Ok(Self {
      filter_type: FilterType(u8::decode(data)?),
      stop_hash: BlockHash::decode(data)?,
    })
  }

  fn encode(&self, buf: &mut Vec<u8>) {
    self.filter_type.0.encode(buf);
    self.stop_hash.encode(buf);
  }
}

crate::codec::impl_p2p!(GetCFCheckpt);

/// Response carrying filter header checkpoints at 1000-block intervals.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct CFCheckpt {
  /// Filter type.
  pub filter_type: FilterType,
  /// Stop block hash.
  pub stop_hash: BlockHash,
  /// Filter headers at every 1000th block.
  pub filter_headers: Vec<BlockHash>,
}

impl Codec for CFCheckpt {
  fn decode(data: &mut &[u8]) -> Result<Self, DecodeError> {
    Ok(Self {
      filter_type: FilterType(u8::decode(data)?),
      stop_hash: BlockHash::decode(data)?,
      filter_headers: Vec::decode(data)?,
    })
  }

  fn encode(&self, buf: &mut Vec<u8>) {
    self.filter_type.0.encode(buf);
    self.stop_hash.encode(buf);
    self.filter_headers.encode(buf);
  }
}

crate::codec::impl_p2p!(CFCheckpt);
