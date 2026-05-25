//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! MnHardFork hard-fork signal (type 7).

use crate::prelude::*;
use crate::validation::{DeploymentContext, VERSIONBITS_NUM_BITS};
use crate::QuorumHash;

use dash_types::codec::{Codec, DecodeError};
use dash_types::BlsSignatureBytes;

use core::fmt;

/// MnHardFork -- hard-fork signal (type 7).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct MnHardFork {
  /// Payload version.
  pub version: u8,
  /// Feature bit being activated.
  pub version_bit: u8,
  /// Quorum hash.
  pub quorum_hash: QuorumHash,
  /// Quorum BLS signature.
  pub sig: BlsSignatureBytes,
}

impl Codec for MnHardFork {
  fn decode(data: &mut &[u8]) -> Result<Self, DecodeError> {
    Ok(Self {
      version: u8::decode(data)?,
      version_bit: u8::decode(data)?,
      quorum_hash: QuorumHash::decode(data)?,
      sig: BlsSignatureBytes::decode(data)?,
    })
  }

  fn encode(&self, buf: &mut Vec<u8>) {
    self.version.encode(buf);
    self.version_bit.encode(buf);
    self.quorum_hash.encode(buf);
    self.sig.encode(buf);
  }
}

crate::codec::impl_payload!(MnHardFork);

impl fmt::Display for MnHardFork {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "MnHardFork {{ v{}, bit: {} }}", self.version, self.version_bit,)
  }
}

/// MNHF signal validation failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MnHardForkInvalid {
  /// `bad-mnhf-version`
  BadVersion { version: u8 },
  /// `bad-mnhf-nbit-out-of-bounds`
  VersionBitOutOfBounds { bit: u8 },
}

impl core::fmt::Display for MnHardForkInvalid {
  fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
    match self {
      Self::BadVersion { version } => write!(f, "bad-mnhf-version: {version}"),
      Self::VersionBitOutOfBounds { bit } => write!(f, "bad-mnhf-nbit-out-of-bounds: {bit}"),
    }
  }
}

impl MnHardFork {
  /// Validates payload invariants.
  ///
  /// # Errors
  ///
  /// Returns the first validation error encountered.
  pub fn validate(&self, _ctx: &DeploymentContext) -> Result<(), MnHardForkInvalid> {
    if self.version == 0 || self.version > 1 {
      return Err(MnHardForkInvalid::BadVersion { version: self.version });
    }

    if self.version_bit >= VERSIONBITS_NUM_BITS {
      return Err(MnHardForkInvalid::VersionBitOutOfBounds { bit: self.version_bit });
    }

    Ok(())
  }
}
