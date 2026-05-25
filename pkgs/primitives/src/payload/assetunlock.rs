//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! AssetUnlock (type 9): Platform to L1.

use crate::prelude::*;
use crate::validation::DeploymentContext;
use crate::QuorumHash;

use dash_types::codec::{Codec, DecodeError};
use dash_types::BlsSignatureBytes;

use core::fmt;

/// AssetUnlock: Platform-to-L1 (type 9).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
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

impl Codec for AssetUnlock {
  fn decode(data: &mut &[u8]) -> Result<Self, DecodeError> {
    Ok(Self {
      version: u8::decode(data)?,
      index: u64::decode(data)?,
      fee: u32::decode(data)?,
      requested_height: u32::decode(data)?,
      quorum_hash: QuorumHash::decode(data)?,
      quorum_sig: BlsSignatureBytes::decode(data)?,
    })
  }

  fn encode(&self, buf: &mut Vec<u8>) {
    self.version.encode(buf);
    self.index.encode(buf);
    self.fee.encode(buf);
    self.requested_height.encode(buf);
    self.quorum_hash.encode(buf);
    self.quorum_sig.encode(buf);
  }
}

crate::codec::impl_payload!(AssetUnlock);

impl fmt::Display for AssetUnlock {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "AssetUnlock {{ v{}, index: {} }}", self.version, self.index,)
  }
}

/// Asset unlock validation failure.
#[derive(Debug, Clone, PartialEq, Eq)]
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
