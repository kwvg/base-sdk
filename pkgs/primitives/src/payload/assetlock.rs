//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! AssetLock (type 8): L1 to Platform.

use crate::error::DecodeError;
use crate::prelude::*;
use crate::tx_out::TxOut;
use crate::validation::DeploymentContext;
use crate::wire;

use bitcoin_consensus_encoding as encoding;

use core::fmt;

/// AssetLock: L1-to-Platform (type 8).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssetLock {
  /// Payload version.
  pub version: u8,
  /// Platform credit allocations.
  pub credit_outputs: Vec<TxOut>,
}

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

impl AssetLock {
  fn decode_for_codec(data: &[u8]) -> Result<Self, crate::codec::DecodeError> {
    Self::decode(data).map_err(Into::into)
  }

  /// Decodes from the extra_payload byte slice.
  pub fn decode(data: &[u8]) -> Result<Self, DecodeError> {
    let sl = &mut &data[..];

    let version = wire::read_u8(sl)?;

    let count = wire::read_compact_size(sl, 100)?;

    let mut credit_outputs = Vec::with_capacity(count);
    for _ in 0..count {
      let raw = wire::read_u64_le(sl)?;
      let value = bitcoin_units::Amount::from_sat(raw)
        .map_err(|_| DecodeError::CompactSizeExceedsLimit { limit: 0, value: raw })?;
      let script_pubkey = wire::read_script(sl, 10_000)?;
      credit_outputs.push(TxOut { value, script_pubkey });
    }

    Ok(Self {
      version,
      credit_outputs,
    })
  }
}

impl encoding::Decodable for AssetLock {
  type Decoder = crate::codec::BufferDecoder<Self, crate::codec::DecodeError>;
  fn decoder() -> Self::Decoder {
    crate::codec::BufferDecoder::new(Self::decode_for_codec, crate::MAX_EXTRA_PAYLOAD_SIZE)
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
