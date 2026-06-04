//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Transaction input.

use crate::outpoint::{OutPoint, OutPointDecoder, OutPointDecoderError, OutPointEncoder};
use crate::script::{Script, ScriptDecoder, ScriptDecoderError, ScriptEncoder};

use bitcoin_consensus_encoding as encoding;

use core::fmt;

/// A transaction input.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct TxIn {
  /// The outpoint being spent.
  pub prevout: OutPoint,
  /// Unlocking script.
  pub script_sig: Script,
  /// Sequence number.
  pub sequence: u32,
}

impl fmt::Display for TxIn {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "TxIn {{ prevout: {}, seq: {} }}", self.prevout, self.sequence,)
  }
}

// Consensus encoding (new ecosystem traits).

encoding::encoder_newtype! {
  /// Encoder for [`TxIn`].
  pub struct TxInEncoder<'e>(
    encoding::Encoder3<OutPointEncoder<'e>, ScriptEncoder<'e>, encoding::ArrayEncoder<4>>
  );
}

impl encoding::Encodable for TxIn {
  type Encoder<'e> = TxInEncoder<'e>;

  fn encoder(&self) -> Self::Encoder<'_> {
    TxInEncoder::new(encoding::Encoder3::new(
      self.prevout.encoder(),
      self.script_sig.encoder(),
      encoding::ArrayEncoder::without_length_prefix(self.sequence.to_le_bytes()),
    ))
  }
}

/// Decoder for [`TxIn`].
#[derive(Debug)]
pub struct TxInDecoder(encoding::Decoder3<OutPointDecoder, ScriptDecoder, encoding::ArrayDecoder<4>>);

impl TxInDecoder {
  /// Constructs a new decoder.
  pub const fn new() -> Self {
    Self(encoding::Decoder3::new(
      OutPointDecoder::new(),
      ScriptDecoder::new(),
      encoding::ArrayDecoder::new(),
    ))
  }
}

impl Default for TxInDecoder {
  fn default() -> Self {
    Self::new()
  }
}

/// Decode error for [`TxIn`].
#[derive(Debug)]
pub enum TxInDecoderError {
  /// Failed to decode the outpoint.
  Outpoint(OutPointDecoderError),
  /// Failed to decode the script sig.
  ScriptSig(ScriptDecoderError),
  /// Failed to decode the sequence number.
  Sequence(encoding::UnexpectedEofError),
}

impl fmt::Display for TxInDecoderError {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    match self {
      Self::Outpoint(e) => write!(f, "txin outpoint: {e}"),
      Self::ScriptSig(e) => write!(f, "txin script_sig: {e}"),
      Self::Sequence(e) => write!(f, "txin sequence: {e}"),
    }
  }
}

impl encoding::Decoder for TxInDecoder {
  type Output = TxIn;
  type Error = TxInDecoderError;

  #[inline]
  fn push_bytes(&mut self, bytes: &mut &[u8]) -> Result<bool, Self::Error> {
    self.0.push_bytes(bytes).map_err(|e| match e {
      encoding::Decoder3Error::First(e) => TxInDecoderError::Outpoint(e),
      encoding::Decoder3Error::Second(e) => TxInDecoderError::ScriptSig(e),
      encoding::Decoder3Error::Third(e) => TxInDecoderError::Sequence(e),
    })
  }

  #[inline]
  fn end(self) -> Result<Self::Output, Self::Error> {
    let (outpoint, script_sig, seq_bytes) = self.0.end().map_err(|e| match e {
      encoding::Decoder3Error::First(e) => TxInDecoderError::Outpoint(e),
      encoding::Decoder3Error::Second(e) => TxInDecoderError::ScriptSig(e),
      encoding::Decoder3Error::Third(e) => TxInDecoderError::Sequence(e),
    })?;
    Ok(TxIn {
      prevout: outpoint,
      script_sig,
      sequence: u32::from_le_bytes(seq_bytes),
    })
  }

  #[inline]
  fn read_limit(&self) -> usize {
    self.0.read_limit()
  }
}

impl encoding::Decodable for TxIn {
  type Decoder = TxInDecoder;
  fn decoder() -> Self::Decoder {
    TxInDecoder::new()
  }
}
