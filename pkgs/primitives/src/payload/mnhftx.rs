//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! MnHardFork hard-fork signal (type 7).

use crate::error::DecodeError;
use crate::validation::{DeploymentContext, VERSIONBITS_NUM_BITS};
use crate::wire;
use crate::QuorumHash;

use bitcoin_consensus_encoding as encoding;
use dash_types::BlsSignatureBytes;

use core::fmt;

/// MnHardFork -- hard-fork signal (type 7).
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
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

impl fmt::Display for MnHardFork {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "MnHardFork {{ v{}, bit: {} }}", self.version, self.version_bit,)
  }
}

impl MnHardFork {
  fn decode_for_codec(data: &[u8]) -> Result<Self, crate::codec::DecodeError> {
    Self::decode(data).map_err(Into::into)
  }

  /// Decodes from the extra_payload byte slice.
  pub fn decode(data: &[u8]) -> Result<Self, DecodeError> {
    let sl = &mut &data[..];

    let version = wire::read_u8(sl)?;
    let version_bit = wire::read_u8(sl)?;
    let quorum_hash = wire::read_hash(sl)?.into();
    let sig = wire::read_type(sl)?;

    Ok(Self {
      version,
      version_bit,
      quorum_hash,
      sig,
    })
  }
}

impl encoding::Decodable for MnHardFork {
  type Decoder = crate::codec::BufferDecoder<Self, crate::codec::DecodeError>;
  fn decoder() -> Self::Decoder {
    crate::codec::BufferDecoder::new(Self::decode_for_codec, crate::MAX_EXTRA_PAYLOAD_SIZE)
  }
}

/// MNHF signal validation failure.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
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
