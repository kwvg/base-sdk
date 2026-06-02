//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Dash transaction with version/type packing and optional extra payload for
//! special transactions.

use crate::outpoint::OutPoint;
use crate::prelude::*;
use crate::tx_in::{TxIn, TxInDecoderError};
use crate::tx_out::{TxOut, TxOutDecoderError};
use crate::tx_types::TxType;
use crate::validation::{DeploymentContext, MAX_COINBASE_SCRIPT_SIZE, MAX_TX_EXTRA_PAYLOAD};

use bitcoin_consensus_encoding as encoding;

use core::fmt;

/// Maximum extra payload size over the wire (100 KB).
pub const MAX_EXTRA_PAYLOAD_SIZE: usize = 100_000;

/// A Dash transaction.
///
/// The wire format packs `version` (i16) and `tx_type` (u16) into a single
/// `i32`: `raw = (tx_type << 16) | (version & 0xffff)`.
///
/// Special transactions (type != Spend, version >= 3) carry an `extra_payload`
/// decoded separately by payload-specific decoders.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Transaction {
  /// Transaction version (lower 16 bits of the wire i32).
  pub version: i16,
  /// Transaction type (upper 16 bits of the wire i32).
  #[cfg_attr(feature = "serde", serde(with = "crate::serialize::uint::w16"))]
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
    let t = (self.tx_type.to_u16() as i32) << 16;
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
      &self.extra_payload,
    ))
  }
}

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

// Ecosystem encoding traits.

type TransactionEncoderInner<'e> = encoding::Encoder2<
  encoding::Encoder4<
    encoding::ArrayEncoder<4>,
    encoding::Encoder2<encoding::CompactSizeEncoder, encoding::SliceEncoder<'e, TxIn>>,
    encoding::Encoder2<encoding::CompactSizeEncoder, encoding::SliceEncoder<'e, TxOut>>,
    encoding::ArrayEncoder<4>,
  >,
  Option<encoding::Encoder2<encoding::CompactSizeEncoder, encoding::BytesEncoder<'e>>>,
>;

encoding::encoder_newtype! {
  /// Encoder for [`Transaction`].
  pub struct TransactionEncoder<'e>(TransactionEncoderInner<'e>);
}

impl encoding::Encodable for Transaction {
  type Encoder<'e> = TransactionEncoder<'e>;

  fn encoder(&self) -> Self::Encoder<'_> {
    let version = encoding::ArrayEncoder::without_length_prefix(self.raw_version().to_le_bytes());
    let inputs = encoding::Encoder2::new(
      encoding::CompactSizeEncoder::new(self.inputs.len()),
      encoding::SliceEncoder::without_length_prefix(&self.inputs),
    );
    let outputs = encoding::Encoder2::new(
      encoding::CompactSizeEncoder::new(self.outputs.len()),
      encoding::SliceEncoder::without_length_prefix(&self.outputs),
    );
    let lock_time = encoding::ArrayEncoder::without_length_prefix(self.lock_time.to_le_bytes());
    let extra = if self.has_extra_payload() {
      Some(encoding::Encoder2::new(
        encoding::CompactSizeEncoder::new(self.extra_payload.len()),
        encoding::BytesEncoder::without_length_prefix(&self.extra_payload),
      ))
    } else {
      None
    };

    TransactionEncoder::new(encoding::Encoder2::new(
      encoding::Encoder4::new(version, inputs, outputs, lock_time),
      extra,
    ))
  }
}

/// Decoder for [`Transaction`].
///
/// State machine that decodes the packed version first, then inputs, outputs,
/// lock_time, and conditionally the extra payload.
#[derive(Clone, Debug)]
pub struct TransactionDecoder {
  state: TxDecoderState,
}

#[derive(Clone, Debug)]
enum TxDecoderState {
  /// Decoding the 4-byte packed version.
  Version(encoding::ArrayDecoder<4>),
  /// Decoding inputs (version already known).
  Inputs {
    version: i16,
    tx_type: TxType,
    dec: encoding::VecDecoder<TxIn>,
  },
  /// Decoding outputs.
  Outputs {
    version: i16,
    tx_type: TxType,
    inputs: Vec<TxIn>,
    dec: encoding::VecDecoder<TxOut>,
  },
  /// Decoding the 4-byte lock_time.
  LockTime {
    version: i16,
    tx_type: TxType,
    inputs: Vec<TxIn>,
    outputs: Vec<TxOut>,
    dec: encoding::ArrayDecoder<4>,
  },
  /// Decoding the extra payload (special tx only).
  ExtraPayload {
    version: i16,
    tx_type: TxType,
    inputs: Vec<TxIn>,
    outputs: Vec<TxOut>,
    lock_time: u32,
    dec: encoding::ByteVecDecoder,
  },
  /// Decoding complete.
  Done(Transaction),
  /// Poisoned after error.
  Poisoned,
}

impl TransactionDecoder {
  /// Constructs a new decoder.
  pub const fn new() -> Self {
    Self {
      state: TxDecoderState::Version(encoding::ArrayDecoder::new()),
    }
  }
}

impl Default for TransactionDecoder {
  fn default() -> Self {
    Self::new()
  }
}

/// Decode error for [`Transaction`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TransactionDecoderError {
  /// Failed to decode the packed version field.
  Version(encoding::UnexpectedEofError),
  /// Failed to decode an input.
  Input(encoding::VecDecoderError<TxInDecoderError>),
  /// Failed to decode an output.
  Output(encoding::VecDecoderError<TxOutDecoderError>),
  /// Failed to decode the lock_time.
  LockTime(encoding::UnexpectedEofError),
  /// Failed to decode the extra payload.
  ExtraPayload(encoding::ByteVecDecoderError),
  /// Decoding ended before completion.
  Incomplete,
}

impl fmt::Display for TransactionDecoderError {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    match self {
      Self::Version(e) => write!(f, "tx version: {e}"),
      Self::Input(e) => write!(f, "tx input: {e}"),
      Self::Output(e) => write!(f, "tx output: {e}"),
      Self::LockTime(e) => write!(f, "tx lock_time: {e}"),
      Self::ExtraPayload(e) => write!(f, "tx extra_payload: {e}"),
      Self::Incomplete => write!(f, "incomplete transaction"),
    }
  }
}

impl encoding::Decoder for TransactionDecoder {
  type Output = Transaction;
  type Error = TransactionDecoderError;

  fn push_bytes(&mut self, bytes: &mut &[u8]) -> Result<bool, Self::Error> {
    loop {
      match core::mem::replace(&mut self.state, TxDecoderState::Poisoned) {
        TxDecoderState::Version(mut dec) => {
          if dec.push_bytes(bytes).map_err(TransactionDecoderError::Version)? {
            self.state = TxDecoderState::Version(dec);
            return Ok(true);
          }
          let buf = dec.end().map_err(TransactionDecoderError::Version)?;
          let raw = i32::from_le_bytes(buf);
          let version = raw as i16;
          let tx_type = TxType::from_u16(((raw >> 16) & 0xffff) as u16);
          self.state = TxDecoderState::Inputs {
            version,
            tx_type,
            dec: encoding::VecDecoder::new(),
          };
        }
        TxDecoderState::Inputs {
          version,
          tx_type,
          mut dec,
        } => {
          if dec.push_bytes(bytes).map_err(TransactionDecoderError::Input)? {
            self.state = TxDecoderState::Inputs { version, tx_type, dec };
            return Ok(true);
          }
          let inputs = dec.end().map_err(TransactionDecoderError::Input)?;
          self.state = TxDecoderState::Outputs {
            version,
            tx_type,
            inputs,
            dec: encoding::VecDecoder::new(),
          };
        }
        TxDecoderState::Outputs {
          version,
          tx_type,
          inputs,
          mut dec,
        } => {
          if dec.push_bytes(bytes).map_err(TransactionDecoderError::Output)? {
            self.state = TxDecoderState::Outputs {
              version,
              tx_type,
              inputs,
              dec,
            };
            return Ok(true);
          }
          let outputs = dec.end().map_err(TransactionDecoderError::Output)?;
          self.state = TxDecoderState::LockTime {
            version,
            tx_type,
            inputs,
            outputs,
            dec: encoding::ArrayDecoder::new(),
          };
        }
        TxDecoderState::LockTime {
          version,
          tx_type,
          inputs,
          outputs,
          mut dec,
        } => {
          if dec.push_bytes(bytes).map_err(TransactionDecoderError::LockTime)? {
            self.state = TxDecoderState::LockTime {
              version,
              tx_type,
              inputs,
              outputs,
              dec,
            };
            return Ok(true);
          }
          let buf = dec.end().map_err(TransactionDecoderError::LockTime)?;
          let lock_time = u32::from_le_bytes(buf);

          if version >= 3 && tx_type != TxType::Spend {
            self.state = TxDecoderState::ExtraPayload {
              version,
              tx_type,
              inputs,
              outputs,
              lock_time,
              dec: encoding::ByteVecDecoder::new_with_limit(MAX_EXTRA_PAYLOAD_SIZE),
            };
          } else {
            self.state = TxDecoderState::Done(Transaction {
              version,
              tx_type,
              inputs,
              outputs,
              lock_time,
              extra_payload: Vec::new(),
            });
            return Ok(false);
          }
        }
        TxDecoderState::ExtraPayload {
          version,
          tx_type,
          inputs,
          outputs,
          lock_time,
          mut dec,
        } => {
          if dec.push_bytes(bytes).map_err(TransactionDecoderError::ExtraPayload)? {
            self.state = TxDecoderState::ExtraPayload {
              version,
              tx_type,
              inputs,
              outputs,
              lock_time,
              dec,
            };
            return Ok(true);
          }
          let extra_payload = dec.end().map_err(TransactionDecoderError::ExtraPayload)?;
          self.state = TxDecoderState::Done(Transaction {
            version,
            tx_type,
            inputs,
            outputs,
            lock_time,
            extra_payload,
          });
          return Ok(false);
        }
        TxDecoderState::Done(_) | TxDecoderState::Poisoned => return Ok(false),
      }
    }
  }

  fn end(self) -> Result<Self::Output, Self::Error> {
    match self.state {
      TxDecoderState::Done(tx) => Ok(tx),
      _ => Err(TransactionDecoderError::Incomplete),
    }
  }

  fn read_limit(&self) -> usize {
    match &self.state {
      TxDecoderState::Version(d) => d.read_limit(),
      TxDecoderState::Inputs { dec, .. } => dec.read_limit(),
      TxDecoderState::Outputs { dec, .. } => dec.read_limit(),
      TxDecoderState::LockTime { dec, .. } => dec.read_limit(),
      TxDecoderState::ExtraPayload { dec, .. } => dec.read_limit(),
      TxDecoderState::Done(_) | TxDecoderState::Poisoned => 0,
    }
  }
}

impl encoding::Decodable for Transaction {
  type Decoder = TransactionDecoder;
  fn decoder() -> Self::Decoder {
    TransactionDecoder::new()
  }
}

/// Transaction validation failure.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
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
