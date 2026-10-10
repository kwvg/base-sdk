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
use dash_types::codec::BaseCodec;
use dash_types::type_id::{TypeId, Unencodable};
use dash_types::{enum_map, impl_num, ArrayBuf, Checkable, Hashable, Numeric};
use hex_conservative::DisplayHex;

use core::fmt;

/// Maximum allowed name length for governance proposals.
const MAX_PROPOSAL_NAME_LEN: usize = 40;

/// Minimum URL length for governance proposals.
const MIN_URL_LEN: usize = 4;

/// Largest data a proposal object may carry, in bytes.
pub const MAX_PROPOSAL_DATA_SIZE: usize = 512;

/// Object type a proposal declares in its data.
const PROPOSAL_TYPE: i64 = 1;

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
#[derive(Clone, Debug, Eq, Hash, PartialEq, Unencodable)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
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
  /// Signature bytes.
  #[cfg_attr(feature = "serde", serde(with = "dash_types::serialize::hex"))]
  pub sig: Vec<u8>,
}

codec_base!(GovVote {
  masternode_outpoint,
  parent_hash,
  outcome,
  signal,
  time,
  sig,
});

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
  };
  const TESTNET: AddrParams = AddrParams {
    pubkey_addr: 140,
    script_addr: 19,
    secret_key: 239,
    ext_pubkey: [0x04, 0x35, 0x87, 0xcf],
    ext_secret: [0x04, 0x35, 0x83, 0x94],
    bip44_idx: 1,
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
    let corpus = Corpus::open(env!("CARGO_MANIFEST_DIR"), "govobjvote");
    let mut vote = corpus
      .entries::<GovVote>("govobjvote", |_, _, _| {})
      .into_values()
      .next()
      .unwrap();
    assert_eq!(vote.check(), None);
    vote.signal = VoteSignal::from_base(signal);
    vote.outcome = VoteOutcome::from_base(outcome);
    assert_eq!(vote.check(), expected);
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
        assert_eq!(parsed.len(), 4, "{label}");
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
