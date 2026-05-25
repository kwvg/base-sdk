//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! CoinbaseCommitment coinbase commitment payload (type 5).

use crate::prelude::*;
use crate::validation::DeploymentContext;
use crate::MerkleRoot;

use bitcoin_units::BlockHeight;
use dash_types::codec::{self, Codec, DecodeError};
use dash_types::BlsSignatureBytes;

use core::fmt;

/// CoinbaseCommitment -- coinbase commitment payload.
///
/// - v1: base fields (version, height, merkle_root_mn_list)
/// - v2: adds merkle_root_quorums
/// - v3: adds ChainLock proof and credit pool balance
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct CoinbaseCommitment {
  /// Payload version (1, 2, or 3).
  pub version: u16,
  /// Block height.
  pub height: BlockHeight,
  /// Merkle root of the masternode list.
  pub merkle_root_mn_list: MerkleRoot,
  /// Merkle root of quorum commitments (v2+).
  pub merkle_root_quorums: Option<MerkleRoot>,
  /// Best ChainLock height difference (v3+, CompactSize).
  pub best_cl_height_diff: Option<u64>,
  /// Best ChainLock BLS signature (v3+).
  pub best_cl_signature: Option<BlsSignatureBytes>,
  /// Credit pool balance in duffs (v3+).
  pub credit_pool_balance: Option<i64>,
}

impl Codec for CoinbaseCommitment {
  fn decode(data: &mut &[u8]) -> Result<Self, DecodeError> {
    let version = u16::decode(data)?;
    let height = BlockHeight::from_u32(u32::decode(data)?);
    let merkle_root_mn_list = MerkleRoot::decode(data)?;
    let merkle_root_quorums = if version >= 2 {
      Some(MerkleRoot::decode(data)?)
    } else {
      None
    };
    let (best_cl_height_diff, best_cl_signature, credit_pool_balance) = if version >= 3 {
      (
        Some(codec::read_compact_u64(data)?),
        Some(BlsSignatureBytes::decode(data)?),
        Some(i64::decode(data)?),
      )
    } else {
      (None, None, None)
    };

    Ok(Self {
      version,
      height,
      merkle_root_mn_list,
      merkle_root_quorums,
      best_cl_height_diff,
      best_cl_signature,
      credit_pool_balance,
    })
  }

  fn encode(&self, buf: &mut Vec<u8>) {
    self.version.encode(buf);
    self.height.to_u32().encode(buf);
    self.merkle_root_mn_list.encode(buf);
    if let Some(ref root) = self.merkle_root_quorums {
      root.encode(buf);
    }
    if let Some(diff) = self.best_cl_height_diff {
      codec::write_compact_u64(diff, buf);
      if let Some(ref sig) = self.best_cl_signature {
        sig.encode(buf);
      }
      if let Some(balance) = self.credit_pool_balance {
        balance.encode(buf);
      }
    }
  }
}

crate::codec::impl_payload!(CoinbaseCommitment);

impl fmt::Display for CoinbaseCommitment {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "CoinbaseCommitment {{ v{}, height: {} }}", self.version, self.height)
  }
}

/// Coinbase commitment validation failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CbTxInvalid {
  /// `bad-cbtx-version`
  BadVersion { version: u16 },
}

impl core::fmt::Display for CbTxInvalid {
  fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
    match self {
      Self::BadVersion { version } => write!(f, "bad-cbtx-version: {version}"),
    }
  }
}

impl CoinbaseCommitment {
  /// Validates version constraints.
  ///
  /// # Errors
  ///
  /// Returns `CbTxInvalid` when the version is invalid or conflicts with
  /// deployment state.
  pub fn validate(&self, ctx: &DeploymentContext) -> Result<(), CbTxInvalid> {
    if self.version == 0 || self.version >= 4 {
      return Err(CbTxInvalid::BadVersion { version: self.version });
    }

    if ctx.dip0008_active == Some(true) && self.version < 2 {
      return Err(CbTxInvalid::BadVersion { version: self.version });
    }

    if ctx.v20_active == Some(true) && self.version < 3 {
      return Err(CbTxInvalid::BadVersion { version: self.version });
    }
    if ctx.v20_active == Some(false) && self.version >= 3 {
      return Err(CbTxInvalid::BadVersion { version: self.version });
    }

    Ok(())
  }
}
