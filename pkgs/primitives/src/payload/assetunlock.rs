//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! AssetUnlock (type 9): Platform to L1.

use crate::error::DecodeError;
use crate::validation::DeploymentContext;
use crate::wire;
use crate::QuorumHash;

use bitcoin_consensus_encoding as encoding;
use dash_types::BlsSignatureBytes;

use core::fmt;

/// AssetUnlock: Platform-to-L1 (type 9).
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct AssetUnlock {
  /// Payload version.
  pub version: u8,
  /// Monotonic withdrawal sequence number.
  pub index: u64,
  /// Duffs deducted from withdrawal.
  pub fee: u32,
  /// Requested block height.
  pub requested_height: u32,
  /// Quorum hash.
  pub quorum_hash: QuorumHash,
  /// Quorum BLS authorization signature.
  pub quorum_sig: BlsSignatureBytes,
}

impl fmt::Display for AssetUnlock {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "AssetUnlock {{ v{}, index: {} }}", self.version, self.index,)
  }
}

impl AssetUnlock {
  fn decode_for_codec(data: &[u8]) -> Result<Self, crate::codec::DecodeError> {
    Self::decode(data).map_err(Into::into)
  }

  /// Decodes from the extra_payload byte slice.
  pub fn decode(data: &[u8]) -> Result<Self, DecodeError> {
    let sl = &mut &data[..];

    let version = wire::read_u8(sl)?;
    let index = wire::read_u64_le(sl)?;
    let fee = wire::read_u32_le(sl)?;
    let requested_height = wire::read_u32_le(sl)?;
    let quorum_hash = wire::read_hash(sl)?.into();
    let quorum_sig = wire::read_type(sl)?;

    Ok(Self {
      version,
      index,
      fee,
      requested_height,
      quorum_hash,
      quorum_sig,
    })
  }
}

impl encoding::Decodable for AssetUnlock {
  type Decoder = crate::codec::BufferDecoder<Self, crate::codec::DecodeError>;
  fn decoder() -> Self::Decoder {
    crate::codec::BufferDecoder::new(Self::decode_for_codec, crate::MAX_EXTRA_PAYLOAD_SIZE)
  }
}

/// Asset unlock validation failure.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum AssetUnlockInvalid {
  /// `bad-assetunlocktx-version`
  BadVersion { version: u8 },
  /// `bad-txns-assetunlock-fee-outofrange`
  FeeOutOfRange { fee: u32 },
}

impl core::fmt::Display for AssetUnlockInvalid {
  fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
    match self {
      Self::BadVersion { version } => write!(f, "bad-assetunlocktx-version: {version}"),
      Self::FeeOutOfRange { fee } => write!(f, "bad-txns-assetunlock-fee-outofrange: {fee}"),
    }
  }
}

impl AssetUnlock {
  /// Validates payload invariants without chain context.
  ///
  /// # Errors
  ///
  /// Returns the first validation error encountered.
  pub fn validate(&self, _ctx: &DeploymentContext) -> Result<(), AssetUnlockInvalid> {
    if self.version == 0 || self.version > 1 {
      return Err(AssetUnlockInvalid::BadVersion { version: self.version });
    }

    if self.fee == 0 {
      return Err(AssetUnlockInvalid::FeeOutOfRange { fee: self.fee });
    }

    Ok(())
  }
}
