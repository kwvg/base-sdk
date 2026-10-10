//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Dash transaction with version/type packing and optional extra payload for
//! special transactions.

use crate::block::MAX_LEGACY_BLOCK_SIZE;
use crate::payload::{
  AssetLockInvalid, AssetUnlockInvalid, PayloadError, PayloadInvalid, SpecialPayload, TxType, MAXIMUM_WITHDRAWALS,
};
use crate::prelude::*;
use crate::{codec_type, hash_impl};

use bitcoin_hashes::sha256d;
use bitcoin_primitives::script::{ScriptPubKeyBuf, ScriptSigBuf};
use bitcoin_units::Amount;
use dash_num::make_hash;
use dash_types::codec::{self, BaseCodec, DecodeError, EncodeBuf};
use dash_types::type_id::{TypeId, Unencodable};
use dash_types::{impl_type, Checkable, CompactSize, Hashable, Numeric};

use core::fmt;

/// Maximum extra payload size in bytes.
pub const MAX_TX_EXTRA_PAYLOAD: usize = 10_000;

/// Opcode that starts an unspendable output.
const OP_RETURN: u8 = 0x6a;

/// Maximum coinbase script size in bytes.
pub const MAX_COINBASE_SCRIPT_SIZE: usize = 100;

make_hash! {
  /// SHA256d hash of a serialized transaction.
  TxHash, 32
}

hash_impl!(TxHash);

/// A reference to a previous transaction output.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub struct OutPoint {
  /// Transaction hash of the referenced output.
  pub hash: TxHash,
  /// Index of the referenced output within the transaction.
  pub index: u32,
}

codec_type!(OutPoint { hash, index });

impl OutPoint {
  /// Returns `true` for the null outpoint (all-zero hash, index `u32::MAX`).
  pub fn is_null(&self) -> bool {
    self.hash.is_null() && self.index == u32::MAX
  }
}

impl fmt::Display for OutPoint {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "{}:{}", self.hash, self.index)
  }
}

/// A transaction input.
#[derive(Clone, Debug, Eq, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub struct TxIn {
  /// The outpoint being spent.
  pub prevout: OutPoint,
  /// Unlocking script.
  pub script_sig: ScriptSigBuf,
  /// Sequence number.
  pub sequence: u32,
}

codec_type!(TxIn {
  prevout,
  script_sig,
  sequence
});

impl fmt::Display for TxIn {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "TxIn {{ prevout: {}, seq: {} }}", self.prevout, self.sequence,)
  }
}

/// A transaction output.
#[derive(Clone, Debug, Eq, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub struct TxOut {
  /// Output value in duffs.
  #[cfg_attr(feature = "serde", serde(with = "crate::serialize::amount"))]
  pub value: Amount,
  /// Locking script.
  #[cfg_attr(feature = "serde", serde(rename = "scriptPubKey"))]
  pub script_pubkey: ScriptPubKeyBuf,
}

impl_type!(TxOut);

impl BaseCodec for TxOut {
  fn decode(data: &mut &[u8]) -> Result<Self, DecodeError> {
    let raw = u64::decode(data)?;
    let value = Amount::from_sat(raw).map_err(|_| DecodeError::InvalidValue {
      expected: vec![Amount::MAX_MONEY.to_sat()],
      actual: raw,
    })?;
    Ok(Self {
      value,
      script_pubkey: ScriptPubKeyBuf::decode(data)?,
    })
  }

  fn encode(&self, buf: &mut impl EncodeBuf) {
    self.value.to_sat().encode(buf);
    self.script_pubkey.encode(buf);
  }
}

hash_impl!(TxOut);

impl fmt::Display for TxOut {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "TxOut {{ value: {} }}", self.value.to_sat())
  }
}

/// Transaction validation failure.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Unencodable)]
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
  /// `bad-txns-payload-not-allowed`
  PayloadNotAllowed,
  /// `bad-cbtx-invalid`
  CoinbaseCommitmentNotCoinbase,
  /// `bad-txns-payload-decode`
  PayloadDecode(PayloadError),
  /// `bad-txns-payload-check`
  PayloadCheck(PayloadInvalid),
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
      Self::PayloadNotAllowed => write!(f, "bad-txns-payload-not-allowed"),
      Self::CoinbaseCommitmentNotCoinbase => write!(f, "bad-cbtx-invalid"),
      Self::PayloadDecode(e) => write!(f, "bad-txns-payload-decode: {e}"),
      Self::PayloadCheck(e) => write!(f, "bad-txns-payload-check: {e}"),
    }
  }
}

/// A Dash transaction.
///
/// The wire format packs `version` (i16) and `tx_type` (u16) into one `i32`,
/// with the version sign-extended before the type is merged in. A negative
/// version therefore encodes with all type bits set, so decoding and
/// re-encoding such a transaction changes its bytes and its hash.
///
/// Special transactions (type != Spend, version >= 3) carry an `extra_payload`
/// decoded separately by payload-specific decoders.
#[derive(Clone, Debug, Eq, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
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

impl_type!(Transaction);

impl BaseCodec for Transaction {
  fn decode(data: &mut &[u8]) -> Result<Self, DecodeError> {
    let raw = i32::decode(data)?;
    let version = raw as i16;
    let tx_type = TxType::from_base(((raw >> 16) & 0xffff) as u16);

    Ok(Self {
      version,
      tx_type,
      inputs: Vec::decode(data)?,
      outputs: Vec::decode(data)?,
      lock_time: u32::decode(data)?,
      extra_payload: if version >= 3 && tx_type != TxType::Spend {
        let len = CompactSize::decode(data)?.into_len(crate::codec::MAX_SPTX_PAYLOAD_SIZE)?;
        codec::read_bytes(data, len)?.to_vec()
      } else {
        Vec::new()
      },
    })
  }

  fn encode(&self, buf: &mut impl EncodeBuf) {
    self.raw_version().encode(buf);
    self.inputs.encode(buf);
    self.outputs.encode(buf);
    self.lock_time.encode(buf);
    if self.has_extra_payload() {
      self.extra_payload.encode(buf);
    }
  }
}

impl Checkable for Transaction {
  type Error = TxInvalid;

  fn check(&self) -> Option<Self::Error> {
    let allows_empty_vin = matches!(
      self.tx_type,
      TxType::QuorumCommitment | TxType::MnhfSignal | TxType::AssetUnlock
    );
    let allows_empty_vout = matches!(self.tx_type, TxType::QuorumCommitment | TxType::MnhfSignal);

    if !allows_empty_vin && self.inputs.is_empty() {
      return Some(TxInvalid::EmptyInputs);
    }
    if !allows_empty_vout && self.outputs.is_empty() {
      return Some(TxInvalid::EmptyOutputs);
    }

    let mut encoded = Vec::new();
    self.encode(&mut encoded);
    if encoded.len() > MAX_LEGACY_BLOCK_SIZE {
      return Some(TxInvalid::Oversize { size: encoded.len() });
    }

    if !self.has_extra_payload() && !self.extra_payload.is_empty() {
      return Some(TxInvalid::PayloadNotAllowed);
    }
    if self.extra_payload.len() > MAX_TX_EXTRA_PAYLOAD {
      return Some(TxInvalid::PayloadOversize {
        size: self.extra_payload.len(),
      });
    }

    let max_money = bitcoin_units::Amount::MAX_MONEY.to_sat();
    let mut total: u64 = 0;
    for (i, output) in self.outputs.iter().enumerate() {
      let sat = output.value.to_sat();
      if sat > max_money {
        return Some(TxInvalid::OutputTooLarge { index: i, value: sat });
      }
      total = total.saturating_add(sat);
      if total > max_money {
        return Some(TxInvalid::OutputTotalTooLarge { total });
      }
    }

    // Duplicate inputs (CVE-2018-17144).
    if self.inputs.len() > 1 {
      let mut seen = BTreeSet::new();
      for input in &self.inputs {
        if !seen.insert(&input.prevout) {
          return Some(TxInvalid::DuplicateInputs {
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
        return Some(TxInvalid::BadCoinbaseScriptLength { len: cb_len });
      }
    } else {
      for (i, input) in self.inputs.iter().enumerate() {
        if input.prevout.is_null() {
          return Some(TxInvalid::NullPrevout { index: i });
        }
      }
    }

    if self.has_extra_payload() && self.tx_type == TxType::CoinbaseCommitment && !self.is_coinbase() {
      return Some(TxInvalid::CoinbaseCommitmentNotCoinbase);
    }

    if self.has_extra_payload() && self.tx_type == TxType::AssetUnlock {
      if let Some(e) = self.check_asset_unlock_shape() {
        return Some(TxInvalid::PayloadCheck(PayloadInvalid::AssetUnlock(e)));
      }
    }

    let locked = if self.has_extra_payload() && self.tx_type == TxType::AssetLock {
      match self.asset_lock_return() {
        Ok(amount) => Some(amount),
        Err(e) => return Some(TxInvalid::PayloadCheck(PayloadInvalid::AssetLock(e))),
      }
    } else {
      None
    };

    if let Some(result) = self.decode_payload() {
      match result {
        Ok(ref payload) if payload.is_unknown() => {
          return Some(TxInvalid::PayloadCheck(PayloadInvalid::UnknownType(self.tx_type)));
        }
        Ok(payload) => {
          if let Some(e) = payload.check() {
            return Some(TxInvalid::PayloadCheck(e));
          }
          if let (SpecialPayload::AssetLock(lock), Some(returned)) = (&payload, locked) {
            let credited = lock.credit_outputs.iter().map(|out| out.value.to_sat()).sum();
            if credited != returned {
              let e = AssetLockInvalid::CreditAmountMismatch { credited, returned };
              return Some(TxInvalid::PayloadCheck(PayloadInvalid::AssetLock(e)));
            }
          }
        }
        Err(e) => return Some(TxInvalid::PayloadDecode(e)),
      }
    }

    None
  }
}

impl Hashable for Transaction {
  type Hash = TxHash;

  fn hash(&self) -> TxHash {
    let mut buf = Vec::new();
    self.encode(&mut buf);
    TxHash::from_lendian(sha256d::Hash::hash(&buf).to_byte_array())
  }
}

impl Transaction {
  /// Returns the packed i32 version field as on the wire.
  pub fn raw_version(&self) -> i32 {
    i32::from(self.version) | (i32::from(self.tx_type.to_base()) << 16)
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
    let mut cursor = &self.extra_payload[..];
    let result = crate::payload::SpecialPayload::decode(self.tx_type, &mut cursor);
    Some(result.and_then(|payload| {
      if !cursor.is_empty() {
        return Err(crate::payload::PayloadError {
          tx_type: self.tx_type,
          message: format!("trailing bytes: {} remaining", cursor.len()),
        });
      }
      Ok(payload)
    }))
  }

  /// Returns the amount an asset lock burns in its one `OP_RETURN` output,
  /// whose script must be `OP_RETURN OP_0`.
  fn asset_lock_return(&self) -> Result<u64, AssetLockInvalid> {
    let max_money = Amount::MAX_MONEY.to_sat();
    let mut returned = 0;
    for (index, output) in self.outputs.iter().enumerate() {
      let script = output.script_pubkey.as_bytes();
      if script.first() != Some(&OP_RETURN) {
        continue;
      }
      if script != [OP_RETURN, 0x00] {
        return Err(AssetLockInvalid::NonEmptyReturn { index });
      }
      let value = output.value.to_sat();
      if value == 0 || value > max_money {
        return Err(AssetLockInvalid::ReturnOutOfRange { index });
      }
      if returned > 0 {
        return Err(AssetLockInvalid::MultipleReturn { index });
      }
      returned = value;
    }
    if returned == 0 {
      return Err(AssetLockInvalid::NoReturn);
    }
    Ok(returned)
  }

  /// Checks that an asset unlock spends nothing and pays few enough outputs.
  fn check_asset_unlock_shape(&self) -> Option<AssetUnlockInvalid> {
    if !self.inputs.is_empty() {
      return Some(AssetUnlockInvalid::HaveInput);
    }
    (self.outputs.len() > MAXIMUM_WITHDRAWALS).then_some(AssetUnlockInvalid::TooManyOutputs {
      count: self.outputs.len(),
    })
  }

  /// Tells whether the transaction is a coinbase. A null first input followed
  /// by more inputs does not make a coinbase.
  pub(crate) fn is_coinbase(&self) -> bool {
    self.inputs.len() == 1 && self.inputs[0].prevout.is_null()
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

#[cfg(all(test, feature = "serde"))]
#[expect(clippy::panic, clippy::unwrap_used, reason = "test code")]
mod tests {
  use super::*;

  use dash_dev::{assert_serde_rt, check_tx, Corpus};
  use rstest::rstest;

  #[rstest]
  #[case("spend")]
  #[case("coinbase")]
  #[case("data")]
  fn corpus_tx(#[case] section: &str) {
    let corpus = Corpus::open(env!("CARGO_MANIFEST_DIR"), section);
    let items = corpus.entries::<Transaction>(section, check_tx);
    assert_serde_rt(section, &items);
  }

  fn bare(version: i16, tx_type: u16) -> Transaction {
    Transaction {
      version,
      tx_type: TxType::from_base(tx_type),
      inputs: Vec::new(),
      outputs: Vec::new(),
      lock_time: 0,
      extra_payload: Vec::new(),
    }
  }

  #[rstest]
  #[case::negative_spend(-1, 0, 0xFFFF_FFFF)]
  #[case::negative_two_spend(-2, 0, 0xFFFF_FFFE)]
  #[case::negative_typed(-1, 5, 0xFFFF_FFFF)]
  #[case::min_typed(i16::MIN, 5, 0xFFFF_8000)]
  #[case::positive_typed(3, 5, 0x0005_0003)]
  #[case::high_type(3, 0x8000, 0x8000_0003)]
  fn packs_the_sign_extended_version(#[case] version: i16, #[case] tx_type: u16, #[case] raw: u32) {
    let tx = bare(version, tx_type);
    assert_eq!(tx.raw_version() as u32, raw);

    let mut buf = Vec::new();
    tx.encode(&mut buf);
    assert_eq!(buf[..4], raw.to_le_bytes());
  }

  #[rstest]
  #[case::all_ones(0xFFFF_FFFF, -1, 0xFFFF, 0xFFFF_FFFF)]
  #[case::negative_spend(0x0000_FFFE, -2, 0, 0xFFFF_FFFE)]
  #[case::negative_typed(0x0005_FFFF, -1, 5, 0xFFFF_FFFF)]
  #[case::min_typed(0x0005_8000, i16::MIN, 5, 0xFFFF_8000)]
  #[case::negative_high_type(0xFFFF_FFFE, -2, 0xFFFF, 0xFFFF_FFFE)]
  #[case::high_type(0x8000_0003, 3, 0x8000, 0x8000_0003)]
  fn unpacks_and_repacks_the_version(
    #[case] raw: u32,
    #[case] version: i16,
    #[case] tx_type: u16,
    #[case] repacked: u32,
  ) {
    // Empty input and output counts and a zero lock time follow the version.
    let mut wire = raw.to_le_bytes().to_vec();
    wire.resize(10, 0x00);
    if version >= 3 && tx_type != 0 {
      wire.push(0x00);
    }

    let tx = Transaction::decode(&mut wire.as_slice()).unwrap();
    assert_eq!((tx.version, tx.tx_type.to_base()), (version, tx_type));
    assert_eq!(tx.raw_version() as u32, repacked);
  }

  fn wire_len(tx: &Transaction) -> usize {
    let mut buf = Vec::new();
    tx.encode(&mut buf);
    buf.len()
  }

  /// Builds a spend whose serialized size is exactly `size` bytes, for any
  /// size large enough to need a five-byte script length prefix.
  fn spend_of_size(size: usize) -> Transaction {
    let mut tx = bare(1, 0);
    tx.inputs.push(TxIn {
      prevout: OutPoint {
        hash: TxHash::from_lendian([0x11; 32]),
        index: 0,
      },
      script_sig: ScriptSigBuf::new(),
      sequence: u32::MAX,
    });
    tx.outputs.push(TxOut {
      value: Amount::ZERO,
      script_pubkey: ScriptPubKeyBuf::from_bytes(vec![0x00; 0x1_0000]),
    });
    let overhead = wire_len(&tx) - 0x1_0000;
    tx.outputs[0].script_pubkey = ScriptPubKeyBuf::from_bytes(vec![0x00; size - overhead]);
    assert_eq!(wire_len(&tx), size);
    tx
  }

  #[rstest]
  fn serialized_size_is_capped_at_the_legacy_block_size() {
    assert_eq!(spend_of_size(MAX_LEGACY_BLOCK_SIZE).check(), None);
    assert_eq!(
      spend_of_size(MAX_LEGACY_BLOCK_SIZE + 1).check(),
      Some(TxInvalid::Oversize {
        size: MAX_LEGACY_BLOCK_SIZE + 1
      })
    );
  }

  fn corpus_asset_unlock() -> Transaction {
    let corpus = Corpus::open(env!("CARGO_MANIFEST_DIR"), "assetunlock");
    let mut raws = Vec::new();
    corpus.entries::<crate::AssetUnlock>("assetunlock", |raw, _, _| raws.push(raw.to_vec()));
    Transaction::decode(&mut raws[0].as_slice()).unwrap()
  }

  #[rstest]
  fn asset_unlock_spends_nothing() {
    let mut tx = corpus_asset_unlock();
    assert_eq!(tx.check(), None);
    tx.inputs.push(TxIn {
      prevout: OutPoint {
        hash: TxHash::from_lendian([0x11; 32]),
        index: 0,
      },
      script_sig: ScriptSigBuf::new(),
      sequence: u32::MAX,
    });
    let error = TxInvalid::PayloadCheck(PayloadInvalid::AssetUnlock(AssetUnlockInvalid::HaveInput));
    assert_eq!(tx.check(), Some(error));
  }

  #[rstest]
  #[case::at_the_limit(MAXIMUM_WITHDRAWALS, None)]
  #[case::past_the_limit(MAXIMUM_WITHDRAWALS + 1, Some(AssetUnlockInvalid::TooManyOutputs { count: MAXIMUM_WITHDRAWALS + 1 }))]
  fn asset_unlock_pays_at_most_32_outputs(#[case] count: usize, #[case] expected: Option<AssetUnlockInvalid>) {
    let mut tx = corpus_asset_unlock();
    let output = tx.outputs[0].clone();
    tx.outputs = vec![output; count];
    assert_eq!(
      tx.check(),
      expected.map(|e| TxInvalid::PayloadCheck(PayloadInvalid::AssetUnlock(e)))
    );
  }

  fn corpus_asset_lock() -> Transaction {
    let corpus = Corpus::open(env!("CARGO_MANIFEST_DIR"), "assetlock");
    let mut raws = Vec::new();
    corpus.entries::<crate::AssetLock>("assetlock", |raw, _, _| raws.push(raw.to_vec()));
    Transaction::decode(&mut raws[0].as_slice()).unwrap()
  }

  fn return_index(tx: &Transaction) -> usize {
    tx.outputs
      .iter()
      .position(|out| out.script_pubkey.as_bytes() == [0x6a, 0x00])
      .unwrap()
  }

  #[rstest]
  #[case::non_empty_return(|tx: &mut Transaction, i: usize| tx.outputs[i].script_pubkey = ScriptPubKeyBuf::from_bytes(vec![0x6a, 0x01]), AssetLockInvalid::NonEmptyReturn { index: 0 })]
  #[case::zero_return(|tx: &mut Transaction, i: usize| tx.outputs[i].value = Amount::ZERO, AssetLockInvalid::ReturnOutOfRange { index: 0 })]
  #[case::multiple_return(|tx: &mut Transaction, i: usize| { let out = tx.outputs[i].clone(); tx.outputs.push(out) }, AssetLockInvalid::MultipleReturn { index: 0 })]
  #[case::no_return(|tx: &mut Transaction, i: usize| { tx.outputs.remove(i); }, AssetLockInvalid::NoReturn)]
  #[case::credit_amount(|tx: &mut Transaction, i: usize| tx.outputs[i].value = Amount::from_sat(tx.outputs[i].value.to_sat() + 1).unwrap(), AssetLockInvalid::CreditAmountMismatch { credited: 0, returned: 0 })]
  fn asset_lock_burns_its_credit_in_one_return(
    #[case] edit: fn(&mut Transaction, usize),
    #[case] fault: AssetLockInvalid,
  ) {
    let mut tx = corpus_asset_lock();
    assert_eq!(tx.check(), None);
    let index = return_index(&tx);
    edit(&mut tx, index);
    let Some(TxInvalid::PayloadCheck(PayloadInvalid::AssetLock(found))) = tx.check() else {
      panic!("{:?}", tx.check());
    };
    assert_eq!(core::mem::discriminant(&found), core::mem::discriminant(&fault));
  }

  #[rstest]
  fn asset_lock_reasons_match_the_reference() {
    let reasons = [
      (
        AssetLockInvalid::NonEmptyReturn { index: 1 },
        "bad-assetlocktx-non-empty-return",
      ),
      (
        AssetLockInvalid::ReturnOutOfRange { index: 1 },
        "bad-assetlocktx-opreturn-outofrange",
      ),
      (
        AssetLockInvalid::MultipleReturn { index: 1 },
        "bad-assetlocktx-multiple-return",
      ),
      (AssetLockInvalid::NoReturn, "bad-assetlocktx-no-return"),
      (
        AssetLockInvalid::CreditAmountMismatch {
          credited: 1,
          returned: 2,
        },
        "bad-assetlocktx-creditamount",
      ),
    ];
    for (error, reason) in reasons {
      assert!(error.to_string().starts_with(reason), "{error}");
    }
  }

  #[rstest]
  fn coinbase_commitment_outside_a_coinbase_is_rejected() {
    let corpus = Corpus::open(env!("CARGO_MANIFEST_DIR"), "cbtx");
    let mut raws = Vec::new();
    corpus.entries::<crate::CoinbaseCommitment>("cbtx", |raw, _, _| raws.push(raw.to_vec()));
    let mut tx = Transaction::decode(&mut raws[0].as_slice()).unwrap();
    assert_eq!(tx.tx_type, TxType::CoinbaseCommitment);
    assert_eq!(tx.check(), None);

    tx.inputs[0].prevout = OutPoint {
      hash: TxHash::from_lendian([0x11; 32]),
      index: 0,
    };
    assert_eq!(tx.check(), Some(TxInvalid::CoinbaseCommitmentNotCoinbase));
    assert_eq!(TxInvalid::CoinbaseCommitmentNotCoinbase.to_string(), "bad-cbtx-invalid");
  }

  #[rstest]
  fn null_first_input_with_more_inputs_is_not_a_coinbase() {
    let corpus = Corpus::open(env!("CARGO_MANIFEST_DIR"), "coinbase");
    let items = corpus.entries::<Transaction>("coinbase", |_, _, _| {});
    let mut tx = items.into_values().find(|tx| tx.tx_type == TxType::Spend).unwrap();
    assert!(tx.is_coinbase());

    let mut extra = tx.inputs[0].clone();
    extra.prevout = OutPoint {
      hash: TxHash::from_lendian([0x11; 32]),
      index: 0,
    };
    tx.inputs.push(extra);
    assert!(!tx.is_coinbase());
    assert_eq!(tx.check(), Some(TxInvalid::NullPrevout { index: 0 }));
  }
}
