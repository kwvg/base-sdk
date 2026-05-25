//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Dash transaction with version/type packing and optional extra payload for
//! special transactions.

use crate::outpoint::OutPoint;
use crate::prelude::*;
use crate::tx_in::TxIn;
use crate::tx_out::TxOut;
use crate::tx_types::TxType;
use crate::validation::{DeploymentContext, MAX_COINBASE_SCRIPT_SIZE, MAX_TX_EXTRA_PAYLOAD};

use dash_types::codec::{self, Codec, DecodeError, NumCodec};

use core::fmt;

/// Maximum extra payload size over the wire (100 KB).
pub const MAX_EXTRA_PAYLOAD_SIZE: usize = 100_000;

/// Maximum number of inputs/outputs.
const MAX_TX_IO: usize = 100_000;

/// A Dash transaction.
///
/// The wire format packs `version` (i16) and `tx_type` (u16) into a single
/// `i32`: `raw = (tx_type << 16) | (version & 0xffff)`.
///
/// Special transactions (type != Spend, version >= 3) carry an `extra_payload`
/// decoded separately by payload-specific decoders.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct Transaction {
  /// Transaction version (lower 16 bits of the wire i32).
  pub version: i16,
  /// Transaction type (upper 16 bits of the wire i32).
  pub tx_type: TxType,
  /// Transaction inputs.
  pub inputs: Vec<TxIn>,
  /// Transaction outputs.
  pub outputs: Vec<TxOut>,
  /// Lock time.
  pub lock_time: u32,
  /// Extra payload for special transactions.
  #[cfg_attr(feature = "serde", serde(with = "dash_types::serialize::hex"))]
  pub extra_payload: Vec<u8>,
}

impl Transaction {
  /// Returns the packed i32 version field as on the wire.
  pub fn raw_version(&self) -> i32 {
    let v = (self.version as u16) as i32;
    let t = (self.tx_type.to_base() as i32) << 16;
    v | t
  }

  /// Returns true when this transaction carries an extra payload.
  fn has_extra_payload(&self) -> bool {
    self.version >= 3 && self.tx_type != TxType::Spend
  }

  /// Decodes the special transaction payload, if present.
  ///
  /// Returns `None` for spend/coinbase transactions that carry no extra
  /// payload.
  ///
  /// # Errors
  ///
  /// Returns `PayloadError` if the payload bytes cannot be decoded for the
  /// declared transaction type.
  pub fn decode_payload(&self) -> Option<Result<crate::payload::SpecialPayload, crate::payload::PayloadError>> {
    if !self.has_extra_payload() {
      return None;
    }
    Some(crate::payload::SpecialPayload::decode(
      self.tx_type,
      &mut &self.extra_payload[..],
    ))
  }
}

impl Codec for Transaction {
  fn decode(data: &mut &[u8]) -> Result<Self, DecodeError> {
    let raw = codec::read_i32_le(data)?;
    let version = raw as i16;
    let tx_type = TxType::from_base(((raw >> 16) & 0xffff) as u16);

    let inputs: Vec<TxIn> = codec::read_vec(data, MAX_TX_IO)?;
    let outputs: Vec<TxOut> = codec::read_vec(data, MAX_TX_IO)?;
    let lock_time = codec::read_u32_le(data)?;

    let extra_payload = if version >= 3 && tx_type != TxType::Spend {
      codec::read_blob(data, MAX_EXTRA_PAYLOAD_SIZE)?
    } else {
      Vec::new()
    };

    Ok(Self {
      version,
      tx_type,
      inputs,
      outputs,
      lock_time,
      extra_payload,
    })
  }

  fn encode(&self, buf: &mut Vec<u8>) {
    buf.extend_from_slice(&self.raw_version().to_le_bytes());
    codec::write_vec(&self.inputs, buf);
    codec::write_vec(&self.outputs, buf);
    buf.extend_from_slice(&self.lock_time.to_le_bytes());
    if self.has_extra_payload() {
      codec::write_blob(&self.extra_payload, buf);
    }
  }
}

dash_types::impl_type!(Transaction);

impl fmt::Display for Transaction {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(
      f,
      "Transaction {{ v{}, {}, {} in, {} out }}",
      self.version,
      self.tx_type,
      self.inputs.len(),
      self.outputs.len(),
    )
  }
}

/// Transaction validation failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TxInvalid {
  /// `bad-txns-vin-empty`
  EmptyInputs,
  /// `bad-txns-vout-empty`
  EmptyOutputs,
  /// `bad-txns-oversize`
  Oversize { size: usize },
  /// `bad-txns-payload-oversize`
  PayloadOversize { size: usize },
  /// `bad-txns-vout-toolarge`
  OutputTooLarge { index: usize, value: u64 },
  /// `bad-txns-txouttotal-toolarge`
  OutputTotalTooLarge { total: u64 },
  /// `bad-txns-inputs-duplicate`
  DuplicateInputs { outpoint: OutPoint },
  /// `bad-cb-length`
  BadCoinbaseScriptLength { len: usize },
  /// `bad-txns-prevout-null`
  NullPrevout { index: usize },
}

impl fmt::Display for TxInvalid {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    match self {
      Self::EmptyInputs => write!(f, "bad-txns-vin-empty"),
      Self::EmptyOutputs => write!(f, "bad-txns-vout-empty"),
      Self::Oversize { size } => write!(f, "bad-txns-oversize: {size} bytes"),
      Self::PayloadOversize { size } => write!(f, "bad-txns-payload-oversize: {size} bytes"),
      Self::OutputTooLarge { index, value } => write!(f, "bad-txns-vout-toolarge: output {index} value {value}"),
      Self::OutputTotalTooLarge { total } => write!(f, "bad-txns-txouttotal-toolarge: {total}"),
      Self::DuplicateInputs { outpoint } => write!(f, "bad-txns-inputs-duplicate: {outpoint}"),
      Self::BadCoinbaseScriptLength { len } => write!(f, "bad-cb-length: {len}"),
      Self::NullPrevout { index } => write!(f, "bad-txns-prevout-null: input {index}"),
    }
  }
}

impl OutPoint {
  /// Returns `true` for the null outpoint (all-zero hash, index `u32::MAX`).
  fn is_null(&self) -> bool {
    self.hash.is_null() && self.index == u32::MAX
  }
}

impl Transaction {
  /// Validates structural invariants without chain context.
  ///
  /// # Errors
  ///
  /// Returns the first validation error encountered.
  pub fn validate(&self, _ctx: &DeploymentContext) -> Result<(), TxInvalid> {
    let allows_empty_vin = matches!(
      self.tx_type,
      TxType::QuorumCommitment | TxType::MnhfSignal | TxType::AssetUnlock
    );
    let allows_empty_vout = matches!(self.tx_type, TxType::QuorumCommitment | TxType::MnhfSignal);

    if !allows_empty_vin && self.inputs.is_empty() {
      return Err(TxInvalid::EmptyInputs);
    }
    if !allows_empty_vout && self.outputs.is_empty() {
      return Err(TxInvalid::EmptyOutputs);
    }

    if self.extra_payload.len() > MAX_TX_EXTRA_PAYLOAD {
      return Err(TxInvalid::PayloadOversize {
        size: self.extra_payload.len(),
      });
    }

    let max_money = bitcoin_units::Amount::MAX_MONEY.to_sat();
    let mut total: u64 = 0;
    for (i, output) in self.outputs.iter().enumerate() {
      let sat = output.value.to_sat();
      if sat > max_money {
        return Err(TxInvalid::OutputTooLarge { index: i, value: sat });
      }
      total = total.saturating_add(sat);
      if total > max_money {
        return Err(TxInvalid::OutputTotalTooLarge { total });
      }
    }

    // Duplicate inputs (CVE-2018-17144).
    if self.inputs.len() > 1 {
      let mut seen = BTreeSet::new();
      for input in &self.inputs {
        if !seen.insert(&input.prevout) {
          return Err(TxInvalid::DuplicateInputs {
            outpoint: input.prevout,
          });
        }
      }
    }

    if self.is_coinbase() {
      let min_cb_size = if self.tx_type == TxType::CoinbaseCommitment {
        1
      } else {
        2
      };
      let cb_len = self.inputs[0].script_sig.len();
      if cb_len < min_cb_size || cb_len > MAX_COINBASE_SCRIPT_SIZE {
        return Err(TxInvalid::BadCoinbaseScriptLength { len: cb_len });
      }
    } else {
      for (i, input) in self.inputs.iter().enumerate() {
        if input.prevout.is_null() {
          return Err(TxInvalid::NullPrevout { index: i });
        }
      }
    }

    Ok(())
  }

  /// Returns `true` when the first input spends the null outpoint.
  pub(crate) fn is_coinbase(&self) -> bool {
    !self.inputs.is_empty() && self.inputs[0].prevout.is_null()
  }
}
