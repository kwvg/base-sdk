//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! AssetLock (type 8): L1 to Platform.

use crate::prelude::*;
use crate::tx_out::TxOut;
use crate::validation::DeploymentContext;

use dash_types::codec::{self, Codec, DecodeError};

use core::fmt;

/// AssetLock: L1-to-Platform (type 8).
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct AssetLock {
  /// Payload version.
  pub version: u8,
  /// Platform credit allocations.
  pub credit_outputs: Vec<TxOut>,
}

impl Codec for AssetLock {
  fn decode(data: &mut &[u8]) -> Result<Self, DecodeError> {
    Ok(Self {
      version: u8::decode(data)?,
      credit_outputs: codec::read_vec(data, 100)?,
    })
  }

  fn encode(&self, buf: &mut Vec<u8>) {
    self.version.encode(buf);
    codec::write_vec(&self.credit_outputs, buf);
  }
}

crate::codec::impl_payload!(AssetLock);

impl fmt::Display for AssetLock {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(
      f,
      "AssetLock {{ v{}, outputs: {} }}",
      self.version,
      self.credit_outputs.len(),
    )
  }
}

/// Asset lock validation failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AssetLockInvalid {
  /// `bad-assetlocktx-version`
  BadVersion { version: u8 },
  /// `bad-assetlocktx-emptycreditoutputs`
  EmptyCreditOutputs,
  /// `bad-assetlocktx-credit-outofrange`
  CreditOutOfRange { index: usize },
  /// `bad-assetlocktx-pubKeyHash`
  CreditNotP2pkh { index: usize },
}

impl core::fmt::Display for AssetLockInvalid {
  fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
    match self {
      Self::BadVersion { version } => write!(f, "bad-assetlocktx-version: {version}"),
      Self::EmptyCreditOutputs => write!(f, "bad-assetlocktx-emptycreditoutputs"),
      Self::CreditOutOfRange { index } => write!(f, "bad-assetlocktx-credit-outofrange: output {index}"),
      Self::CreditNotP2pkh { index } => write!(f, "bad-assetlocktx-pubKeyHash: output {index}"),
    }
  }
}

impl AssetLock {
  /// Validates payload invariants without chain context.
  ///
  /// # Errors
  ///
  /// Returns the first validation error encountered.
  pub fn validate(&self, _ctx: &DeploymentContext) -> Result<(), AssetLockInvalid> {
    if self.version == 0 || self.version > 1 {
      return Err(AssetLockInvalid::BadVersion { version: self.version });
    }

    if self.credit_outputs.is_empty() {
      return Err(AssetLockInvalid::EmptyCreditOutputs);
    }

    let max_money = bitcoin_units::Amount::MAX_MONEY.to_sat();
    let mut total: u64 = 0;
    for (i, out) in self.credit_outputs.iter().enumerate() {
      let sat = out.value.to_sat();
      if sat == 0 || sat > max_money {
        return Err(AssetLockInvalid::CreditOutOfRange { index: i });
      }
      total = total.saturating_add(sat);
      if total > max_money {
        return Err(AssetLockInvalid::CreditOutOfRange { index: i });
      }
      if !dash_script::is_p2pkh(out.script_pubkey.as_bytes()) {
        return Err(AssetLockInvalid::CreditNotP2pkh { index: i });
      }
    }

    Ok(())
  }
}
