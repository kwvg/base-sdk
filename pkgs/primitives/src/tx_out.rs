//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Transaction output.

use crate::script::{Script, ScriptDecoder, ScriptDecoderError, ScriptEncoder};

use bitcoin_consensus_encoding as encoding;
use bitcoin_units::Amount;

use core::fmt;

/// A transaction output.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct TxOut {
  /// Output value in duffs.
  #[cfg_attr(feature = "serde", serde(with = "crate::serialize::amount"))]
  pub value: Amount,
  /// Locking script.
  pub script_pubkey: Script,
}

impl fmt::Display for TxOut {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "TxOut {{ value: {} }}", self.value.to_sat())
  }
}

encoding::encoder_newtype! {
  /// Encoder for [`TxOut`].
  pub struct TxOutEncoder<'e>(
    encoding::Encoder2<encoding::ArrayEncoder<8>, ScriptEncoder<'e>>
  );
}

impl encoding::Encodable for TxOut {
  type Encoder<'e> = TxOutEncoder<'e>;

  fn encoder(&self) -> Self::Encoder<'_> {
    TxOutEncoder::new(encoding::Encoder2::new(
      encoding::ArrayEncoder::without_length_prefix(self.value.to_sat().to_le_bytes()),
      self.script_pubkey.encoder(),
    ))
  }
}

/// Decoder for [`TxOut`].
#[derive(Clone, Debug)]
pub struct TxOutDecoder(encoding::Decoder2<encoding::ArrayDecoder<8>, ScriptDecoder>);

impl TxOutDecoder {
  /// Constructs a new decoder.
  pub const fn new() -> Self {
    Self(encoding::Decoder2::new(
      encoding::ArrayDecoder::new(),
      ScriptDecoder::new(),
    ))
  }
}

impl Default for TxOutDecoder {
  fn default() -> Self {
    Self::new()
  }
}

/// Decode error for [`TxOut`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TxOutDecoderError {
  /// Failed to decode the value field.
  Value(encoding::UnexpectedEofError),
  /// Failed to decode the script field.
  Script(ScriptDecoderError),
  /// Value exceeds MAX_MONEY.
  OutOfRange(u64),
}

impl fmt::Display for TxOutDecoderError {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    match self {
      Self::Value(e) => write!(f, "txout value: {e}"),
      Self::Script(e) => write!(f, "txout script: {e}"),
      Self::OutOfRange(v) => write!(f, "txout value {v} exceeds MAX_MONEY"),
    }
  }
}

impl encoding::Decoder for TxOutDecoder {
  type Output = TxOut;
  type Error = TxOutDecoderError;

  #[inline]
  fn push_bytes(&mut self, bytes: &mut &[u8]) -> Result<bool, Self::Error> {
    self.0.push_bytes(bytes).map_err(|e| match e {
      encoding::Decoder2Error::First(e) => TxOutDecoderError::Value(e),
      encoding::Decoder2Error::Second(e) => TxOutDecoderError::Script(e),
    })
  }

  #[inline]
  fn end(self) -> Result<Self::Output, Self::Error> {
    let (value_bytes, script) = self.0.end().map_err(|e| match e {
      encoding::Decoder2Error::First(e) => TxOutDecoderError::Value(e),
      encoding::Decoder2Error::Second(e) => TxOutDecoderError::Script(e),
    })?;
    let raw = u64::from_le_bytes(value_bytes);
    let value = Amount::from_sat(raw).map_err(|_| TxOutDecoderError::OutOfRange(raw))?;
    Ok(TxOut {
      value,
      script_pubkey: script,
    })
  }

  #[inline]
  fn read_limit(&self) -> usize {
    self.0.read_limit()
  }
}

impl encoding::Decodable for TxOut {
  type Decoder = TxOutDecoder;
  fn decoder() -> Self::Decoder {
    TxOutDecoder::new()
  }
}
