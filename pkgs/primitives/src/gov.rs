//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Governance object and vote types as defined by the Dash protocol.

use crate::prelude::*;
use crate::transaction::OutPoint;
use crate::{codec_base, hash_impl, TxHash};

use bitcoin_hashes::sha256d;
use bitcoin_units::Amount;
use dash_num::Hash256;
use dash_script::{AddrParams, Recipient};
use dash_types::codec::{self, BaseCodec, DecodeError, EncodeBuf};
use dash_types::type_id::{TypeId, Unencodable};
use dash_types::{enum_map, impl_num, impl_type, ArrayBuf, Checkable, Hashable, Numeric};
use hex_conservative::DisplayHex;

use core::fmt;

/// Maximum allowed name length for governance proposals.
const MAX_PROPOSAL_NAME_LEN: usize = 40;

/// Minimum URL length for governance proposals.
const MIN_URL_LEN: usize = 4;

/// Largest data a proposal object may carry, in bytes.
pub const MAX_PROPOSAL_DATA_SIZE: usize = 512;

/// Length of a compact ECDSA vote signature.
const VOTE_COMPACT_SIG_SIZE: usize = 65;

/// Length of a BLS vote signature.
const VOTE_BLS_SIG_SIZE: usize = 96;

/// Object type a proposal declares in its data.
const PROPOSAL_TYPE: i64 = 1;

/// Object type a trigger declares in its data.
#[cfg(feature = "serde")]
const TRIGGER_TYPE: i64 = 2;

/// Longest payment amount a trigger may list, in characters.
const MAX_PAYMENT_AMOUNT_LEN: usize = 20;

/// Decimal places of a coin amount.
const COIN_DECIMALS: usize = 8;

/// Allowed characters in governance proposal names.
const PROPOSAL_NAME_CHARS: &[u8] = b"-_abcdefghijklmnopqrstuvwxyz0123456789";

enum_map! {
  /// Governance object type codes.
  #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, TypeId)]
  pub enum GovObjectType, i32, Unknown {
    /// Budget proposal.
    Proposal = 1 => "proposal",
    /// Superblock trigger.
    Trigger = 2 => "trigger",
  }
}

impl_num!(GovObjectType, i32);

hash_impl!(GovObjectType);

/// A governance proposal payload (type 1 JSON).
///
/// ```json
/// {
///   "type": 1,
///   "name": "proposal-name",
///   "url": "https://example.com/proposal",
///   "payment_address": "XaddressHere",
///   "payment_amount": 10.5,
///   "start_epoch": 1700000000,
///   "end_epoch": 1703000000
/// }
/// ```
#[derive(Clone, Debug, Eq, Hash, PartialEq, Unencodable)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct Proposal {
  /// Declared object type, which must be 1.
  #[cfg_attr(feature = "serde", serde(rename = "type"))]
  pub object_type: i64,
  /// Short name (max 40 chars, lowercase alphanum + `-_`).
  pub name: String,
  /// Proposal URL.
  pub url: String,
  /// Dash address receiving payment.
  pub payment_address: String,
  /// Payment amount, a number of coins in JSON.
  #[cfg_attr(feature = "serde", serde(with = "crate::serialize::coins"))]
  pub payment_amount: Amount,
  /// Unix timestamp when payments begin.
  pub start_epoch: i64,
  /// Unix timestamp when payments end.
  pub end_epoch: i64,
}

/// A superblock trigger payload (type 2 JSON).
///
/// ```json
/// {
///   "type": 2,
///   "event_block_height": 123456,
///   "payment_addresses": "addr1|addr2",
///   "payment_amounts": "10.5|20.0",
///   "proposal_hashes": "hash1|hash2"
/// }
/// ```
///
/// Deserializing rejects data whose `type` is not the integer 2.
#[derive(Clone, Debug, Eq, Hash, PartialEq, Unencodable)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(try_from = "__TriggerFields", into = "__TriggerFields"))]
pub struct Trigger {
  /// Block height at which payments occur.
  pub event_block_height: i32,
  /// Pipe-delimited payment addresses.
  pub payment_addresses: String,
  /// Pipe-delimited payment amounts.
  pub payment_amounts: String,
  /// Pipe-delimited proposal hashes.
  pub proposal_hashes: String,
}

/// Field set that carries the declared type of a trigger.
#[cfg(feature = "serde")]
#[derive(::serde::Serialize, ::serde::Deserialize)]
struct __TriggerFields {
  event_block_height: i32,
  payment_addresses: String,
  payment_amounts: String,
  proposal_hashes: String,
  #[serde(rename = "type")]
  object_type: i64,
}

#[cfg(feature = "serde")]
impl TryFrom<__TriggerFields> for Trigger {
  type Error = String;

  fn try_from(fields: __TriggerFields) -> Result<Self, Self::Error> {
    if fields.object_type != TRIGGER_TYPE {
      return Err(format!("trigger type is not {TRIGGER_TYPE}: {}", fields.object_type));
    }
    Ok(Self {
      event_block_height: fields.event_block_height,
      payment_addresses: fields.payment_addresses,
      payment_amounts: fields.payment_amounts,
      proposal_hashes: fields.proposal_hashes,
    })
  }
}

#[cfg(feature = "serde")]
impl From<Trigger> for __TriggerFields {
  fn from(trigger: Trigger) -> Self {
    Self {
      event_block_height: trigger.event_block_height,
      payment_addresses: trigger.payment_addresses,
      payment_amounts: trigger.payment_amounts,
      proposal_hashes: trigger.proposal_hashes,
      object_type: TRIGGER_TYPE,
    }
  }
}

/// One payment of a superblock schedule.
#[derive(Clone, Debug, Eq, Hash, PartialEq, Unencodable)]
pub struct SuperblockPayment {
  /// Recipient of the payment.
  pub recipient: Recipient,
  /// Amount paid.
  pub amount: Amount,
  /// Hash of the proposal the payment funds.
  pub proposal_hash: Hash256,
}

/// Trigger payment schedule failure.
#[derive(Clone, Debug, Eq, Hash, PartialEq, Unencodable)]
pub enum TriggerInvalid {
  /// The address, amount and proposal hash lists differ in length.
  MismatchedPayments,
  /// The address of a payment is not a P2PKH or P2SH address of the network.
  BadAddress { index: usize },
  /// The amount of a payment is not a decimal number of coins in the money
  /// range.
  BadAmount { index: usize },
  /// The proposal hash of a payment is not 64 hex digits.
  BadProposalHash { index: usize },
}

impl fmt::Display for TriggerInvalid {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    match self {
      Self::MismatchedPayments => write!(f, "mismatched payments, amounts and proposal hashes"),
      Self::BadAddress { index } => write!(f, "invalid address of payment {index}"),
      Self::BadAmount { index } => write!(f, "invalid amount of payment {index}"),
      Self::BadProposalHash { index } => write!(f, "invalid proposal hash of payment {index}"),
    }
  }
}

impl Trigger {
  /// Payments the superblock at [`Trigger::event_block_height`] makes, in
  /// list order, for the network `params` describes.
  ///
  /// # Errors
  ///
  /// Returns a [`TriggerInvalid`] for the first list or payment that does not
  /// parse.
  pub fn payments(&self, params: &AddrParams) -> Result<Vec<SuperblockPayment>, TriggerInvalid> {
    let addresses: Vec<_> = self.payment_addresses.split('|').collect();
    let amounts: Vec<_> = self.payment_amounts.split('|').collect();
    let hashes: Vec<_> = self.proposal_hashes.split('|').collect();
    if addresses.len() != amounts.len() || addresses.len() != hashes.len() {
      return Err(TriggerInvalid::MismatchedPayments);
    }
    let payments = addresses.iter().zip(&amounts).zip(&hashes);
    payments
      .enumerate()
      .map(|(index, ((address, amount), hash))| {
        Ok(SuperblockPayment {
          recipient: Recipient::from_base58c(address, params).ok_or(TriggerInvalid::BadAddress { index })?,
          amount: parse_payment_amount(amount).ok_or(TriggerInvalid::BadAmount { index })?,
          proposal_hash: parse_proposal_hash(hash).ok_or(TriggerInvalid::BadProposalHash { index })?,
        })
      })
      .collect()
  }
}

/// Parses a payment amount of at most [`MAX_PAYMENT_AMOUNT_LEN`] characters,
/// written as a decimal number of coins without sign, exponent or leading
/// zeros. Digits past the eighth decimal must be zeros.
fn parse_payment_amount(text: &str) -> Option<Amount> {
  if text.len() > MAX_PAYMENT_AMOUNT_LEN {
    return None;
  }
  let (whole, fraction) = text.split_once('.').unwrap_or((text, "0"));
  let is_digits = |part: &str| !part.is_empty() && part.bytes().all(|b| b.is_ascii_digit());
  if !is_digits(whole) || !is_digits(fraction) || (whole.len() > 1 && whole.starts_with('0')) {
    return None;
  }
  let (decimals, rest) = fraction.split_at(fraction.len().min(COIN_DECIMALS));
  if rest.bytes().any(|b| b != b'0') {
    return None;
  }
  let scale = 10u64.pow((COIN_DECIMALS - decimals.len()) as u32);
  let duffs = whole
    .parse::<u64>()
    .ok()?
    .checked_mul(Amount::ONE_BTC.to_sat())?
    .checked_add(decimals.parse::<u64>().ok()? * scale)?;
  Amount::from_sat(duffs).ok()
}

/// Parses a proposal hash written as exactly 64 hex digits.
fn parse_proposal_hash(text: &str) -> Option<Hash256> {
  (text.len() == 64 && text.bytes().all(|b| b.is_ascii_hexdigit()))
    .then(|| Hash256::from_hex(text).ok())
    .flatten()
}

/// Decoded governance object data payload.
#[derive(Clone, Debug, Eq, Hash, PartialEq, Unencodable)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub enum GovData {
  /// Budget proposal.
  Proposal(Proposal),
  /// Superblock trigger.
  Trigger(Trigger),
  /// Opaque data for unknown types.
  Unknown(Vec<u8>),
}

/// A governance object as serialized on the wire.
///
/// ```text
/// hash_parent(32) || revision(i32) || time(i64)
/// || collateral_hash(32) || data(CompactSize + bytes)
/// || type(i32) || masternode_outpoint(36)
/// || sig(CompactSize + bytes)
/// ```
#[derive(Clone, Debug, Eq, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub struct GovObject {
  /// Parent object hash (zero for root).
  pub hash_parent: TxHash,
  /// Object revision.
  pub revision: i32,
  /// Creation timestamp.
  pub time: i64,
  /// Collateral transaction hash.
  pub collateral_hash: TxHash,
  /// Raw data bytes (JSON when decoded as string).
  #[cfg_attr(feature = "serde", serde(with = "dash_types::serialize::hex"))]
  pub data: Vec<u8>,
  /// Object type code.
  pub object_type: GovObjectType,
  /// Signing masternode outpoint.
  pub masternode_outpoint: OutPoint,
  /// BLS or ECDSA signature.
  #[cfg_attr(feature = "serde", serde(with = "dash_types::serialize::hex"))]
  pub sig: Vec<u8>,
}

codec_base!(GovObject {
  hash_parent,
  revision,
  time,
  collateral_hash,
  data,
  object_type,
  masternode_outpoint,
  sig,
});

impl Hashable for GovObject {
  type Hash = Hash256;

  /// Computes the canonical governance object hash.
  ///
  /// The hash input differs from the wire format: `collateral_hash` and
  /// `object_type` are excluded, and `data` is hex-encoded as ASCII bytes
  /// before hashing.
  fn hash(&self) -> Hash256 {
    let data_hex = self.data.to_lower_hex_string();

    let mut buf = Vec::new();
    self.hash_parent.encode(&mut buf);
    self.revision.encode(&mut buf);
    self.time.encode(&mut buf);
    // data hex is serialized as a string (CompactSize + bytes)
    data_hex.encode(&mut buf);
    // outpoint + dummy padding for legacy hash compat
    self.masternode_outpoint.hash.encode(&mut buf);
    self.masternode_outpoint.index.encode(&mut buf);
    0u8.encode(&mut buf);
    0xFFFF_FFFFu32.encode(&mut buf);
    self.sig.encode(&mut buf);

    Hash256::from_lendian(sha256d::Hash::hash(&buf).to_byte_array())
  }
}

impl GovObject {
  /// Rejects proposal data longer than [`MAX_PROPOSAL_DATA_SIZE`], which the
  /// data must meet before it parses as a proposal.
  pub fn check_proposal_data(&self) -> Option<ProposalInvalid> {
    (self.object_type == GovObjectType::Proposal && self.data.len() > MAX_PROPOSAL_DATA_SIZE)
      .then_some(ProposalInvalid::DataTooLarge { len: self.data.len() })
  }

  /// Returns the data as a UTF-8 string, if valid.
  pub fn data_as_string(&self) -> Option<&str> {
    core::str::from_utf8(&self.data).ok()
  }

  /// Returns the data as a hex string.
  pub fn data_as_hex(&self) -> String {
    self.data.to_lower_hex_string()
  }
}

enum_map! {
  /// Governance vote outcome.
  #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, TypeId)]
  pub enum VoteOutcome, u32, Unknown {
    /// No vote cast.
    None = 0 => "none",
    /// Vote in favour.
    Yes = 1 => "yes",
    /// Vote against.
    No = 2 => "no",
    /// Abstention.
    Abstain = 3 => "abstain",
  }
}

impl_num!(VoteOutcome, u32);

hash_impl!(VoteOutcome);

enum_map! {
  /// Governance vote signal type.
  #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, TypeId)]
  pub enum VoteSignal, u32, Unknown {
    /// No signal.
    None = 0 => "none",
    /// Fund this object.
    Funding = 1 => "funding",
    /// Object checks out.
    Valid = 2 => "valid",
    /// Object should be deleted.
    Delete = 3 => "delete",
    /// Officially endorsed.
    Endorsed = 4 => "endorsed",
  }
}

impl_num!(VoteSignal, u32);

hash_impl!(VoteSignal);

/// A governance vote.
///
/// ```text
/// masternode_outpoint(36) || parent_hash(32)
/// || outcome(u32) || signal(u32) || time(i64)
/// || sig(CompactSize + bytes)
/// ```
#[derive(Clone, Debug, Eq, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub struct GovVote {
  /// Voting masternode outpoint.
  pub masternode_outpoint: OutPoint,
  /// Hash of the governance object being voted on.
  pub parent_hash: TxHash,
  /// Vote outcome.
  pub outcome: VoteOutcome,
  /// Vote signal type.
  pub signal: VoteSignal,
  /// Vote timestamp.
  pub time: i64,
  /// Signature bytes. Decoding rejects a signature that is neither 65 nor 96
  /// bytes.
  #[cfg_attr(feature = "serde", serde(with = "dash_types::serialize::hex"))]
  pub sig: Vec<u8>,
}

impl BaseCodec for GovVote {
  fn decode(data: &mut &[u8]) -> Result<Self, DecodeError> {
    let masternode_outpoint = OutPoint::decode(data)?;
    let parent_hash = TxHash::decode(data)?;
    let outcome = VoteOutcome::decode(data)?;
    let signal = VoteSignal::decode(data)?;
    let time = i64::decode(data)?;
    let sig = codec::read_bytes_limited(data, VOTE_BLS_SIG_SIZE)?;
    if sig.len() != VOTE_COMPACT_SIG_SIZE && sig.len() != VOTE_BLS_SIG_SIZE {
      return Err(DecodeError::BadLen {
        expected: vec![VOTE_COMPACT_SIG_SIZE, VOTE_BLS_SIG_SIZE],
        actual: sig.len(),
      });
    }
    Ok(Self {
      masternode_outpoint,
      parent_hash,
      outcome,
      signal,
      time,
      sig: sig.to_vec(),
    })
  }

  fn encode(&self, buf: &mut impl EncodeBuf) {
    self.masternode_outpoint.encode(buf);
    self.parent_hash.encode(buf);
    self.outcome.encode(buf);
    self.signal.encode(buf);
    self.time.encode(buf);
    self.sig.encode(buf);
  }
}

impl_type!(GovVote);

/// Governance vote validation failure.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Unencodable)]
pub enum GovVoteInvalid {
  /// The signal is not one of the known signals.
  BadSignal { signal: VoteSignal },
  /// The outcome is not one of the known outcomes.
  BadOutcome { outcome: VoteOutcome },
}

impl fmt::Display for GovVoteInvalid {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    match self {
      Self::BadSignal { signal } => write!(f, "invalid signal {signal}"),
      Self::BadOutcome { outcome } => write!(f, "invalid outcome {outcome}"),
    }
  }
}

/// Checks the signal and outcome ranges. The time bound needs a clock and
/// is the caller's.
impl Checkable for GovVote {
  type Error = GovVoteInvalid;

  fn check(&self) -> Option<Self::Error> {
    if matches!(self.signal, VoteSignal::Unknown(_)) {
      return Some(GovVoteInvalid::BadSignal { signal: self.signal });
    }
    matches!(self.outcome, VoteOutcome::Unknown(_)).then_some(GovVoteInvalid::BadOutcome { outcome: self.outcome })
  }
}

impl Hashable for GovVote {
  type Hash = Hash256;

  /// Computes the canonical vote hash, including dummy padding after the
  /// outpoint for legacy compatibility.
  fn hash(&self) -> Hash256 {
    let mut buf = ArrayBuf::<89>::new();
    // outpoint + dummy padding for legacy hash compat
    self.masternode_outpoint.hash.encode(&mut buf);
    self.masternode_outpoint.index.encode(&mut buf);
    0u8.encode(&mut buf);
    0xFFFF_FFFFu32.encode(&mut buf);
    self.parent_hash.encode(&mut buf);
    self.signal.encode(&mut buf);
    self.outcome.encode(&mut buf);
    self.time.encode(&mut buf);

    Hash256::from_lendian(sha256d::Hash::hash(&buf.into_array()).to_byte_array())
  }
}

/// Governance proposal validation failure.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Unencodable)]
pub enum ProposalInvalid {
  /// Data exceeds [`MAX_PROPOSAL_DATA_SIZE`].
  DataTooLarge { len: usize },
  /// Declared type is not a proposal.
  BadType { object_type: i64 },
  /// Name is empty.
  NameEmpty,
  /// Name exceeds maximum length.
  NameTooLong { len: usize },
  /// Name contains invalid characters.
  NameInvalidChars,
  /// `end_epoch` is not after `start_epoch`.
  BadEpochRange,
  /// Payment amount is not positive.
  BadPaymentAmount,
  /// URL is too short.
  UrlTooShort { len: usize },
  /// URL contains whitespace.
  UrlWhitespace,
  /// URL has an unbalanced bracket in its network location.
  UrlInvalid,
  /// Payment address contains whitespace.
  AddressWhitespace,
  /// Payment address is not a P2PKH or P2SH address of the network.
  AddressInvalid,
}

impl fmt::Display for ProposalInvalid {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    match self {
      Self::DataTooLarge { len } => write!(f, "data exceeds {MAX_PROPOSAL_DATA_SIZE} characters: {len}"),
      Self::BadType { object_type } => write!(f, "type is not {PROPOSAL_TYPE}: {object_type}"),
      Self::NameEmpty => write!(f, "invalid name: empty"),
      Self::NameTooLong { len } => write!(f, "invalid name: {len} chars exceeds {MAX_PROPOSAL_NAME_LEN}"),
      Self::NameInvalidChars => write!(f, "invalid name: disallowed characters"),
      Self::BadEpochRange => write!(f, "invalid start:end range"),
      Self::BadPaymentAmount => write!(f, "invalid payment amount"),
      Self::UrlTooShort { len } => write!(f, "url too short: {len} chars"),
      Self::UrlWhitespace => write!(f, "url has whitespace"),
      Self::UrlInvalid => write!(f, "url invalid"),
      Self::AddressWhitespace => write!(f, "payment_address can't have whitespaces"),
      Self::AddressInvalid => write!(f, "payment_address is invalid"),
    }
  }
}

impl Checkable for Proposal {
  type Error = ProposalInvalid;

  /// Checks everything but the payment address, which needs the network and
  /// is checked by [`Proposal::check_payment_address`].
  fn check(&self) -> Option<Self::Error> {
    if self.object_type != PROPOSAL_TYPE {
      return Some(ProposalInvalid::BadType {
        object_type: self.object_type,
      });
    }
    if self.name.is_empty() {
      return Some(ProposalInvalid::NameEmpty);
    }
    if self.name.len() > MAX_PROPOSAL_NAME_LEN {
      return Some(ProposalInvalid::NameTooLong { len: self.name.len() });
    }
    if !self
      .name
      .bytes()
      .all(|b| PROPOSAL_NAME_CHARS.contains(&b.to_ascii_lowercase()))
    {
      return Some(ProposalInvalid::NameInvalidChars);
    }

    if self.end_epoch <= self.start_epoch {
      return Some(ProposalInvalid::BadEpochRange);
    }

    if self.payment_amount == Amount::ZERO {
      return Some(ProposalInvalid::BadPaymentAmount);
    }

    if self.url.bytes().any(is_space) {
      return Some(ProposalInvalid::UrlWhitespace);
    }
    if self.url.len() < MIN_URL_LEN {
      return Some(ProposalInvalid::UrlTooShort { len: self.url.len() });
    }
    if !url_brackets_balance(self.url.as_bytes()) {
      return Some(ProposalInvalid::UrlInvalid);
    }

    None
  }
}

impl Proposal {
  /// Rejects a payment address that is not a P2PKH or P2SH address of the
  /// network `params` describes.
  pub fn check_payment_address(&self, params: &AddrParams) -> Option<ProposalInvalid> {
    if self.payment_address.bytes().any(is_space) {
      return Some(ProposalInvalid::AddressWhitespace);
    }
    Recipient::from_base58c(&self.payment_address, params)
      .is_none()
      .then_some(ProposalInvalid::AddressInvalid)
  }
}

/// Tells whether `b` is a space, tab, line feed, vertical tab, form feed or
/// carriage return.
fn is_space(b: u8) -> bool {
  matches!(b, b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r')
}

/// Tells whether the network location of `url`, the part after `//` up to the
/// path, query or fragment, holds both brackets or neither.
fn url_brackets_balance(url: &[u8]) -> bool {
  let rest = match url.iter().position(|&b| b == b':') {
    Some(pos) => &url[pos + 1..],
    None => url,
  };
  let Some(after) = rest.strip_prefix(b"//").filter(|_| rest.len() > 2) else {
    return true;
  };
  let end = after.iter().position(|b| b"/?#".contains(b)).unwrap_or(after.len());
  let netloc = &after[..end];
  netloc.contains(&b'[') == netloc.contains(&b']')
}

#[cfg(all(test, feature = "serde"))]
#[expect(clippy::panic, clippy::unwrap_used, reason = "test code")]
mod tests {
  use super::*;

  use dash_dev::{assert_serde_rt, check_wire, from_json, from_json_slice, json_rejects, to_json, Corpus, Value};
  use rstest::rstest;
  use serde::{Deserialize, Serialize};

  fn to_value<T: Serialize>(value: &T) -> Value {
    from_json(&to_json(value))
  }

  fn proposal_json(amount: &str) -> String {
    format!(
      r#"{{"type":1,"name":"p","url":"https://x.org","payment_address":"X","payment_amount":{amount},"start_epoch":1,"end_epoch":2}}"#
    )
  }

  #[rstest]
  #[case::whole("200", 200 * 100_000_000)]
  #[case::fraction("10.5", 1_050_000_000)]
  #[case::one_duff("0.00000001", 1)]
  #[case::float_whole("2.0", 200_000_000)]
  fn payment_amount_is_in_coins(#[case] json: &str, #[case] sat: u64) {
    let proposal: Proposal = from_json(&proposal_json(json));
    assert_eq!(proposal.payment_amount.to_sat(), sat);
    let back: Proposal = from_json(&to_json(&proposal));
    assert_eq!(back, proposal);
  }

  #[rstest]
  #[case::whole(200 * 100_000_000, "200")]
  #[case::fraction(1_050_000_000, "10.5")]
  fn payment_amount_serializes_as_coins(#[case] sat: u64, #[case] json: &str) {
    let mut proposal: Proposal = from_json(&proposal_json("1"));
    proposal.payment_amount = Amount::from_sat(sat).unwrap();
    assert_eq!(to_value(&proposal)["payment_amount"], from_json::<Value>(json));
  }

  #[rstest]
  #[case::negative("-1")]
  #[case::negative_float("-0.5")]
  #[case::string("\"10.5\"")]
  fn payment_amount_rejects_non_coin_numbers(#[case] json: &str) {
    assert!(json_rejects::<Proposal>(&proposal_json(json)));
  }

  /// Address prefixes of mainnet and testnet, for the address checks.
  const MAINNET: AddrParams = AddrParams {
    pubkey_addr: 76,
    script_addr: 16,
    secret_key: 204,
    ext_pubkey: [0x04, 0x88, 0xb2, 0x1e],
    ext_secret: [0x04, 0x88, 0xad, 0xe4],
    bip44_idx: 5,
    platform_hrp: "dash",
  };
  const TESTNET: AddrParams = AddrParams {
    pubkey_addr: 140,
    script_addr: 19,
    secret_key: 239,
    ext_pubkey: [0x04, 0x35, 0x87, 0xcf],
    ext_secret: [0x04, 0x35, 0x83, 0x94],
    bip44_idx: 1,
    platform_hrp: "tdash",
  };

  fn proposal_with(edit: impl FnOnce(&mut Proposal)) -> Proposal {
    let mut proposal: Proposal = from_json(&proposal_json("1"));
    proposal.payment_address = String::from("XgNfgrEB9n6uCY9Pi1hb2foimxPdtiZ4Z2");
    edit(&mut proposal);
    proposal
  }

  #[rstest]
  #[case::two(2)]
  #[case::zero(0)]
  fn type_is_not_1(#[case] object_type: i64) {
    let proposal = proposal_with(|p| p.object_type = object_type);
    assert_eq!(proposal.check(), Some(ProposalInvalid::BadType { object_type }));
  }

  #[rstest]
  #[case::string(r#""1""#)]
  #[case::float("1.0")]
  #[case::missing("")]
  fn type_must_be_a_json_integer(#[case] value: &str) {
    let json = proposal_json("1");
    let json = if value.is_empty() {
      json.replace(r#""type":1,"#, "")
    } else {
      json.replace(r#""type":1"#, &format!(r#""type":{value}"#))
    };
    assert!(json_rejects::<Proposal>(&json));
  }

  #[rstest]
  #[case::at_the_limit(MAX_PROPOSAL_DATA_SIZE, None)]
  #[case::past_the_limit(MAX_PROPOSAL_DATA_SIZE + 1, Some(ProposalInvalid::DataTooLarge { len: MAX_PROPOSAL_DATA_SIZE + 1 }))]
  fn data_exceeds_512_characters(#[case] len: usize, #[case] expected: Option<ProposalInvalid>) {
    let corpus = Corpus::open(env!("CARGO_MANIFEST_DIR"), "proposals");
    let mut raws = Vec::new();
    corpus.entries::<Value>("proposals", |raw, _, _| raws.push(raw.to_vec()));
    let mut obj = GovObject::decode(&mut raws[0].as_slice()).unwrap();
    obj.data = vec![b' '; len];
    assert_eq!(obj.check_proposal_data(), expected);
    obj.object_type = GovObjectType::Trigger;
    assert_eq!(obj.check_proposal_data(), None);
  }

  #[rstest]
  #[case::space("Xg Nf")]
  #[case::vertical_tab("XgNf\u{0b}")]
  fn payment_address_cant_have_whitespaces(#[case] address: &str) {
    let proposal = proposal_with(|p| p.payment_address = String::from(address));
    assert_eq!(
      proposal.check_payment_address(&MAINNET),
      Some(ProposalInvalid::AddressWhitespace)
    );
  }

  #[rstest]
  #[case::p2pkh("XgNfgrEB9n6uCY9Pi1hb2foimxPdtiZ4Z2", &MAINNET, None)]
  #[case::p2sh("7mUyau75ATy1c6LoZeG3D57jKBkR4iHJkE", &MAINNET, None)]
  #[case::other_network("XgNfgrEB9n6uCY9Pi1hb2foimxPdtiZ4Z2", &TESTNET, Some(ProposalInvalid::AddressInvalid))]
  #[case::garbage("not-an-address", &MAINNET, Some(ProposalInvalid::AddressInvalid))]
  fn payment_address_is_invalid(
    #[case] address: &str,
    #[case] params: &AddrParams,
    #[case] expected: Option<ProposalInvalid>,
  ) {
    let proposal = proposal_with(|p| p.payment_address = String::from(address));
    assert_eq!(proposal.check_payment_address(params), expected);
  }

  #[rstest]
  #[case::space("https://x.org/a b")]
  #[case::vertical_tab("https://x.org/\u{0b}")]
  fn url_cant_have_whitespaces(#[case] url: &str) {
    let proposal = proposal_with(|p| p.url = String::from(url));
    assert_eq!(proposal.check(), Some(ProposalInvalid::UrlWhitespace));
  }

  #[rstest]
  fn url_too_short() {
    let proposal = proposal_with(|p| p.url = String::from("a.b"));
    assert_eq!(proposal.check(), Some(ProposalInvalid::UrlTooShort { len: 3 }));
  }

  #[rstest]
  #[case::open_only("http://[::1/path", Some(ProposalInvalid::UrlInvalid))]
  #[case::close_only("http://::1]/path", Some(ProposalInvalid::UrlInvalid))]
  #[case::balanced("http://[::1]:80/path", None)]
  #[case::bracket_in_path("http://x.org/[a", None)]
  #[case::no_netloc("mailto:[a", None)]
  fn url_invalid(#[case] url: &str, #[case] expected: Option<ProposalInvalid>) {
    let proposal = proposal_with(|p| p.url = String::from(url));
    assert_eq!(proposal.check(), expected);
  }

  fn trigger_json(object_type: &str) -> String {
    format!(
      r#"{{"event_block_height":160,"payment_addresses":"a","payment_amounts":"1","proposal_hashes":"h"{object_type}}}"#
    )
  }

  #[rstest]
  fn trigger_type_is_2() {
    let trigger: Trigger = from_json(&trigger_json(r#","type":2"#));
    assert_eq!(to_value(&trigger)["type"], from_json::<Value>("2"));
    assert_eq!(from_json::<Trigger>(&to_json(&trigger)), trigger);
  }

  #[rstest]
  #[case::proposal(r#","type":1"#)]
  #[case::string(r#","type":"2""#)]
  #[case::float(r#","type":2.0"#)]
  #[case::missing("")]
  fn trigger_type_must_be_the_integer_2(#[case] object_type: &str) {
    assert!(json_rejects::<Trigger>(&trigger_json(object_type)));
  }

  #[rstest]
  #[case::whole("200", Some(200 * 100_000_000))]
  #[case::zero("0", Some(0))]
  #[case::zero_fraction("0.5", Some(50_000_000))]
  #[case::eight_decimals("1.23456789", Some(123_456_789))]
  #[case::trailing_zero_decimals("1.234567890000", Some(123_456_789))]
  #[case::ninth_decimal("1.000000001", None)]
  #[case::max_money("21000000", Some(21_000_000 * 100_000_000))]
  #[case::past_max_money("21000000.00000001", None)]
  #[case::twenty_chars("1.000000000000000000", Some(100_000_000))]
  #[case::twenty_one_chars("1.0000000000000000000", None)]
  #[case::overflow("99999999999999999999", None)]
  #[case::empty("", None)]
  #[case::leading_point(".5", None)]
  #[case::trailing_point("1.", None)]
  #[case::two_points("1.2.3", None)]
  #[case::leading_zero("01", None)]
  #[case::double_zero("00", None)]
  #[case::sign("-1", None)]
  #[case::exponent("1e8", None)]
  #[case::space(" 1", None)]
  fn payment_amounts_are_fixed_point_coins(#[case] text: &str, #[case] duffs: Option<u64>) {
    assert_eq!(parse_payment_amount(text).map(Amount::to_sat), duffs);
  }

  const HASH: &str = "df6e0fe06a5e388a46c903cdbde8702f6e7d1f9c08340a8d80755fb7e7865ae2";

  #[rstest]
  #[case::lower(HASH, true)]
  #[case::upper("DF6E0FE06A5E388A46C903CDBDE8702F6E7D1F9C08340A8D80755FB7E7865AE2", true)]
  #[case::short(&HASH[1..], false)]
  #[case::prefixed("0xdf6e0fe06a5e388a46c903cdbde8702f6e7d1f9c08340a8d80755fb7e7865a", false)]
  #[case::leading_space(" f6e0fe06a5e388a46c903cdbde8702f6e7d1f9c08340a8d80755fb7e7865ae2", false)]
  #[case::non_hex("gf6e0fe06a5e388a46c903cdbde8702f6e7d1f9c08340a8d80755fb7e7865ae2", false)]
  fn proposal_hashes_are_64_hex_digits(#[case] text: &str, #[case] ok: bool) {
    let parsed = parse_proposal_hash(text);
    assert_eq!(parsed.is_some(), ok);
    if ok {
      assert_eq!(parsed, Hash256::from_hex(HASH).ok());
    }
  }

  fn trigger_with(addresses: &str, amounts: &str, hashes: &str) -> Trigger {
    Trigger {
      event_block_height: 160,
      payment_addresses: String::from(addresses),
      payment_amounts: String::from(amounts),
      proposal_hashes: String::from(hashes),
    }
  }

  const ADDRESS: &str = "XgNfgrEB9n6uCY9Pi1hb2foimxPdtiZ4Z2";

  #[rstest]
  #[case::fewer_amounts(&format!("{ADDRESS}|{ADDRESS}"), "1", &format!("{HASH}|{HASH}"))]
  #[case::fewer_hashes(&format!("{ADDRESS}|{ADDRESS}"), "1|2", HASH)]
  #[case::fewer_addresses(ADDRESS, "1|2", &format!("{HASH}|{HASH}"))]
  fn payment_lists_must_match_in_length(#[case] addresses: &str, #[case] amounts: &str, #[case] hashes: &str) {
    let trigger = trigger_with(addresses, amounts, hashes);
    assert_eq!(trigger.payments(&MAINNET), Err(TriggerInvalid::MismatchedPayments));
  }

  #[rstest]
  #[case::address(&format!("{ADDRESS}|yZLYHtcDsBM5VRMuBZf3QPFNf5YLHUkVbP"), "1|2", TriggerInvalid::BadAddress { index: 1 })]
  #[case::empty_address("", "1", TriggerInvalid::BadAddress { index: 0 })]
  #[case::amount(&format!("{ADDRESS}|{ADDRESS}"), "1|2.", TriggerInvalid::BadAmount { index: 1 })]
  fn bad_payment_fails_the_schedule(#[case] addresses: &str, #[case] amounts: &str, #[case] expected: TriggerInvalid) {
    let count = amounts.split('|').count();
    let hashes = vec![HASH; count].join("|");
    assert_eq!(
      trigger_with(addresses, amounts, &hashes).payments(&MAINNET),
      Err(expected)
    );
  }

  #[rstest]
  fn bad_proposal_hash_fails_the_schedule() {
    let trigger = trigger_with(ADDRESS, "1", &HASH[1..]);
    assert_eq!(
      trigger.payments(&MAINNET),
      Err(TriggerInvalid::BadProposalHash { index: 0 })
    );
  }

  #[rstest]
  fn corpus_trigger_pays_its_schedule() {
    let corpus = Corpus::open(env!("CARGO_MANIFEST_DIR"), "triggers");
    let mut raws = Vec::new();
    corpus.entries::<Value>("triggers", |raw, _, _| raws.push(raw.to_vec()));
    let obj = GovObject::decode(&mut raws[0].as_slice()).unwrap();
    let trigger: Trigger = from_json_slice(&obj.data);
    let payments = trigger.payments(&TESTNET).unwrap();
    let amounts: Vec<_> = payments.iter().map(|payment| payment.amount.to_sat()).collect();
    assert_eq!(amounts, [220_000_000, 110_000_000, 330_000_000]);
    let hashes: Vec<_> = trigger
      .proposal_hashes
      .split('|')
      .map(|hash| Hash256::from_hex(hash).unwrap())
      .collect();
    let proposal_hashes: Vec<_> = payments.iter().map(|payment| payment.proposal_hash).collect();
    assert_eq!(proposal_hashes, hashes);
    let recipients: Vec<_> = trigger
      .payment_addresses
      .split('|')
      .map(|address| Recipient::from_base58c(address, &TESTNET).unwrap())
      .collect();
    let payees: Vec<_> = payments.into_iter().map(|payment| payment.recipient).collect();
    assert_eq!(payees, recipients);
    assert!(trigger.payments(&MAINNET).is_err());
  }

  #[rstest]
  fn zero_payment_amount_fails_the_check() {
    let proposal: Proposal = from_json(&proposal_json("0"));
    assert_eq!(proposal.check(), Some(ProposalInvalid::BadPaymentAmount));
  }

  #[rstest]
  #[case::endorsed(4, 3, None)]
  #[case::signal_unknown(5, 1, Some(GovVoteInvalid::BadSignal { signal: VoteSignal::Unknown(5) }))]
  #[case::outcome_unknown(1, 4, Some(GovVoteInvalid::BadOutcome { outcome: VoteOutcome::Unknown(4) }))]
  #[case::both_unknown(9, 9, Some(GovVoteInvalid::BadSignal { signal: VoteSignal::Unknown(9) }))]
  fn vote_signal_and_outcome_are_in_range(
    #[case] signal: u32,
    #[case] outcome: u32,
    #[case] expected: Option<GovVoteInvalid>,
  ) {
    let mut vote = corpus_vote();
    assert_eq!(vote.check(), None);
    vote.signal = VoteSignal::from_base(signal);
    vote.outcome = VoteOutcome::from_base(outcome);
    assert_eq!(vote.check(), expected);
  }

  fn corpus_vote() -> GovVote {
    let corpus = Corpus::open(env!("CARGO_MANIFEST_DIR"), "govobjvote");
    corpus
      .entries::<GovVote>("govobjvote", |_, _, _| {})
      .into_values()
      .next()
      .unwrap()
  }

  fn bad_len(len: usize) -> Result<(), DecodeError> {
    Err(DecodeError::BadLen {
      expected: vec![65, 96],
      actual: len,
    })
  }

  #[rstest]
  #[case::empty(0, bad_len(0))]
  #[case::short_compact(64, bad_len(64))]
  #[case::compact(65, Ok(()))]
  #[case::long_compact(66, bad_len(66))]
  #[case::short_bls(95, bad_len(95))]
  #[case::bls(96, Ok(()))]
  #[case::past_bls(97, Err(DecodeError::CompactSizeExceedsLimit { limit: 96, value: 97 }))]
  fn vote_signatures_decode_at_65_or_96_bytes(#[case] len: usize, #[case] expected: Result<(), DecodeError>) {
    let vote = GovVote {
      sig: vec![0xAB; len],
      ..corpus_vote()
    };
    let mut wire = Vec::new();
    vote.encode(&mut wire);
    assert_eq!(GovVote::decode(&mut wire.as_slice()), expected.map(|()| vote));
  }

  #[rstest]
  fn corpus_govobjvote() {
    let corpus = Corpus::open(env!("CARGO_MANIFEST_DIR"), "govobjvote");
    let items = corpus.entries::<GovVote>("govobjvote", check_wire);
    assert_serde_rt("govobjvote", &items);
  }

  #[rstest]
  fn corpus_govobj_wire() {
    let corpus = Corpus::open(env!("CARGO_MANIFEST_DIR"), "govobj");
    corpus.entries::<Value>("govobj", |raw, _, label| {
      let decoded = GovObject::decode(&mut &raw[..]).unwrap();
      let mut encoded = Vec::new();
      decoded.encode(&mut encoded);
      assert_eq!(encoded, raw, "{label}: encode");
    });
  }

  /// Corpus representation of a governance object.
  ///
  /// Mirrors [`GovObject`] but stores the inner `data` payload as
  /// structured JSON instead of a hex blob.
  #[derive(Debug, PartialEq, Serialize, Deserialize)]
  #[serde(rename_all = "camelCase")]
  struct GovCorpusDetails {
    hash_parent: TxHash,
    revision: i32,
    collateral_hash: TxHash,
    object_type: GovObjectType,
    time: i64,
    masternode_outpoint: OutPoint,
    #[serde(with = "dash_types::serialize::hex")]
    sig: Vec<u8>,
    data: Value,
  }

  impl GovCorpusDetails {
    fn assert_matches(&self, obj: &GovObject, label: &str) {
      assert_eq!(self.hash_parent, obj.hash_parent, "{label}: hash_parent");
      assert_eq!(self.revision, obj.revision, "{label}: revision");
      assert_eq!(self.time, obj.time, "{label}: time");
      assert_eq!(self.collateral_hash, obj.collateral_hash, "{label}: collateral_hash");
      assert_eq!(self.object_type, obj.object_type, "{label}: object_type");
      assert_eq!(
        self.masternode_outpoint, obj.masternode_outpoint,
        "{label}: masternode_outpoint"
      );
      assert_eq!(self.sig, obj.sig, "{label}: sig");

      let wire_data: Value = from_json_slice(&obj.data);
      assert_eq!(self.data, wire_data, "{label}: data");
    }
  }

  #[rstest]
  #[case("proposals")]
  #[case("triggers")]
  fn corpus_govobj(#[case] section: &str) {
    let corpus = Corpus::open(env!("CARGO_MANIFEST_DIR"), section);
    let items = corpus.entries::<GovCorpusDetails>(section, |raw, details, label| {
      let obj = GovObject::decode(&mut &raw[..]).unwrap();
      details.assert_matches(&obj, label);

      if obj.object_type == GovObjectType::Proposal {
        let proposal: Proposal = from_json_slice(&obj.data);
        if let Some(e) = proposal.check() {
          panic!("{label}: proposal check: {e}");
        }
        assert_eq!(obj.check_proposal_data(), None, "{label}");
        assert_eq!(proposal.check_payment_address(&MAINNET), None, "{label}");
        let Value::Object(fields) = &details.data else {
          panic!("{label}: proposal data is not an object");
        };
        let amount = &fields["payment_amount"];
        assert_eq!(
          to_value(&proposal)["payment_amount"],
          *amount,
          "{label}: payment_amount"
        );
        assert_eq!(
          proposal.payment_amount.to_sat(),
          amount.as_u64().unwrap() * 100_000_000,
          "{label}"
        );
      }

      if obj.object_type == GovObjectType::Trigger {
        let trigger: Trigger = from_json_slice(&obj.data);
        let Value::Object(fields) = &details.data else {
          panic!("{label}: trigger data is not an object");
        };
        let Value::Object(parsed) = to_value(&trigger) else {
          panic!("{label}: trigger does not serialize as an object");
        };
        for (key, value) in &parsed {
          assert_eq!(fields.get(key), Some(value), "{label}: {key}");
        }
        assert_eq!(parsed.len(), 5, "{label}");
        let payments = trigger.payments(&MAINNET).or_else(|_| trigger.payments(&TESTNET));
        assert!(payments.is_ok(), "{label}: payments");
      }

      let mut encoded = Vec::new();
      obj.encode(&mut encoded);
      assert_eq!(encoded, raw, "{label}: encode");

      let expected_hash = Hash256::from_hex(label).unwrap();
      assert_eq!(obj.hash(), expected_hash, "{label}: hash");
    });
    assert_serde_rt(section, &items);
  }
}
