//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Governance object and vote types as defined by the Dash protocol.

use crate::outpoint::OutPoint;
use crate::prelude::*;
use crate::validation::{MAX_PROPOSAL_NAME_LEN, MIN_URL_LEN, PROPOSAL_NAME_CHARS};
use crate::TxHash;

use bitcoin_hashes::sha256d;
use dash_types::codec::{self, Codec, DecodeError};
use hex_conservative::DisplayHex;

use core::fmt;

/// Governance object type codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub enum GovObjectType {
  /// Unknown or unrecognized type.
  Unknown,
  /// Budget proposal.
  Proposal,
  /// Superblock trigger.
  Trigger,
}

impl GovObjectType {
  /// Converts from a raw `i32`.
  pub const fn from_i32(val: i32) -> Self {
    match val {
      1 => Self::Proposal,
      2 => Self::Trigger,
      _ => Self::Unknown,
    }
  }

  /// Converts to a raw `i32`.
  pub const fn to_i32(self) -> i32 {
    match self {
      Self::Unknown => 0,
      Self::Proposal => 1,
      Self::Trigger => 2,
    }
  }
}

impl fmt::Display for GovObjectType {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    match self {
      Self::Unknown => write!(f, "unknown"),
      Self::Proposal => write!(f, "proposal"),
      Self::Trigger => write!(f, "trigger"),
    }
  }
}

/// A governance proposal payload (type 1 JSON).
///
/// ```json
/// {
///   "type": 1,
///   "name": "proposal-name",
///   "url": "https://example.com/proposal",
///   "payment_address": "XaddressHere",
///   "payment_amount": "10.5",
///   "start_epoch": 1700000000,
///   "end_epoch": 1703000000
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct Proposal {
  /// Short name (max 40 chars, lowercase alphanum + `-_`).
  pub name: String,
  /// Proposal URL.
  pub url: String,
  /// Dash address receiving payment.
  pub payment_address: String,
  /// Payment amount in DASH as a decimal string.
  pub payment_amount: String,
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
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
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
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
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
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
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
  pub data: Vec<u8>,
  /// Object type code.
  pub object_type: GovObjectType,
  /// Signing masternode outpoint.
  pub masternode_outpoint: OutPoint,
  /// BLS or ECDSA signature.
  pub sig: Vec<u8>,
}

impl Codec for GovObject {
  fn decode(data: &mut &[u8]) -> Result<Self, DecodeError> {
    let hash_parent = TxHash::decode(data)?;
    let revision = codec::read_i32_le(data)?;
    let time = codec::read_i64_le(data)?;
    let collateral_hash = TxHash::decode(data)?;
    let obj_data = codec::read_blob(data, 16_384)?;
    let object_type = GovObjectType::from_i32(codec::read_i32_le(data)?);
    let mn_hash = TxHash::decode(data)?;
    let mn_index = codec::read_u32_le(data)?;
    let masternode_outpoint = OutPoint {
      hash: mn_hash,
      index: mn_index,
    };
    let sig = codec::read_blob(data, 1024)?;

    Ok(Self {
      hash_parent,
      revision,
      time,
      collateral_hash,
      data: obj_data,
      object_type,
      masternode_outpoint,
      sig,
    })
  }

  fn encode(&self, buf: &mut Vec<u8>) {
    buf.extend_from_slice(self.hash_parent.as_bytes());
    buf.extend_from_slice(&self.revision.to_le_bytes());
    buf.extend_from_slice(&self.time.to_le_bytes());
    buf.extend_from_slice(self.collateral_hash.as_bytes());
    codec::write_blob(&self.data, buf);
    buf.extend_from_slice(&self.object_type.to_i32().to_le_bytes());
    buf.extend_from_slice(self.masternode_outpoint.hash.as_bytes());
    buf.extend_from_slice(&self.masternode_outpoint.index.to_le_bytes());
    codec::write_blob(&self.sig, buf);
  }
}

dash_types::impl_type!(GovObject);

impl GovObject {
  /// Computes the canonical governance object hash.
  ///
  /// The hash input differs from the wire format: `collateral_hash` and
  /// `object_type` are excluded, and `data` is hex-encoded as ASCII bytes
  /// before hashing.
  pub fn hash(&self) -> TxHash {
    let data_hex = self.data.to_lower_hex_string();

    let mut buf = Vec::new();
    buf.extend_from_slice(self.hash_parent.as_bytes());
    buf.extend_from_slice(&self.revision.to_le_bytes());
    buf.extend_from_slice(&self.time.to_le_bytes());
    // data hex is serialized as a string (CompactSize + bytes)
    codec::write_blob(data_hex.as_bytes(), &mut buf);
    // outpoint + dummy padding for legacy hash compat
    buf.extend_from_slice(self.masternode_outpoint.hash.as_bytes());
    buf.extend_from_slice(&self.masternode_outpoint.index.to_le_bytes());
    buf.push(0x00);
    buf.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
    codec::write_blob(&self.sig, &mut buf);

    TxHash::from_bytes(sha256d::Hash::hash(&buf).to_byte_array())
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

/// A governance vote.
///
/// ```text
/// masternode_outpoint(36) || parent_hash(32)
/// || outcome(i32) || signal(i32) || time(i64)
/// || sig(CompactSize + bytes)
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct GovVote {
  /// Voting masternode outpoint.
  pub masternode_outpoint: OutPoint,
  /// Hash of the governance object being voted on.
  pub parent_hash: TxHash,
  /// Vote outcome (yes/no/abstain).
  pub outcome: i32,
  /// Vote signal (funding/valid/delete/endorsed).
  pub signal: i32,
  /// Vote timestamp.
  pub time: i64,
  /// Signature bytes.
  pub sig: Vec<u8>,
}

impl Codec for GovVote {
  fn decode(data: &mut &[u8]) -> Result<Self, DecodeError> {
    let mn_hash = TxHash::decode(data)?;
    let mn_index = codec::read_u32_le(data)?;
    let masternode_outpoint = OutPoint {
      hash: mn_hash,
      index: mn_index,
    };
    let parent_hash = TxHash::decode(data)?;
    let outcome = codec::read_i32_le(data)?;
    let signal = codec::read_i32_le(data)?;
    let time = codec::read_i64_le(data)?;
    let sig = codec::read_blob(data, 1024)?;

    Ok(Self {
      masternode_outpoint,
      parent_hash,
      outcome,
      signal,
      time,
      sig,
    })
  }

  fn encode(&self, buf: &mut Vec<u8>) {
    buf.extend_from_slice(self.masternode_outpoint.hash.as_bytes());
    buf.extend_from_slice(&self.masternode_outpoint.index.to_le_bytes());
    buf.extend_from_slice(self.parent_hash.as_bytes());
    buf.extend_from_slice(&self.outcome.to_le_bytes());
    buf.extend_from_slice(&self.signal.to_le_bytes());
    buf.extend_from_slice(&self.time.to_le_bytes());
    codec::write_blob(&self.sig, buf);
  }
}

dash_types::impl_type!(GovVote);

impl GovVote {
  /// Computes the canonical vote hash, including dummy padding after the
  /// outpoint for legacy compatibility.
  pub fn hash(&self) -> TxHash {
    let mut buf = Vec::new();
    // outpoint + dummy padding for legacy hash compat
    buf.extend_from_slice(self.masternode_outpoint.hash.as_bytes());
    buf.extend_from_slice(&self.masternode_outpoint.index.to_le_bytes());
    buf.push(0x00);
    buf.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
    buf.extend_from_slice(self.parent_hash.as_bytes());
    buf.extend_from_slice(&self.signal.to_le_bytes());
    buf.extend_from_slice(&self.outcome.to_le_bytes());
    buf.extend_from_slice(&self.time.to_le_bytes());

    TxHash::from_bytes(sha256d::Hash::hash(&buf).to_byte_array())
  }
}

/// Governance proposal validation failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProposalInvalid {
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
}

impl fmt::Display for ProposalInvalid {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    match self {
      Self::NameEmpty => write!(f, "invalid name: empty"),
      Self::NameTooLong { len } => write!(f, "invalid name: {len} chars exceeds {MAX_PROPOSAL_NAME_LEN}"),
      Self::NameInvalidChars => write!(f, "invalid name: disallowed characters"),
      Self::BadEpochRange => write!(f, "invalid start:end range"),
      Self::BadPaymentAmount => write!(f, "invalid payment amount"),
      Self::UrlTooShort { len } => write!(f, "url too short: {len} chars"),
      Self::UrlWhitespace => write!(f, "url has whitespace"),
    }
  }
}

impl Proposal {
  /// Validates proposal fields without chain context.
  ///
  /// # Errors
  ///
  /// Returns the first validation error encountered.
  pub fn validate(&self) -> Result<(), ProposalInvalid> {
    if self.name.is_empty() {
      return Err(ProposalInvalid::NameEmpty);
    }
    if self.name.len() > MAX_PROPOSAL_NAME_LEN {
      return Err(ProposalInvalid::NameTooLong { len: self.name.len() });
    }
    if !self
      .name
      .bytes()
      .all(|b| PROPOSAL_NAME_CHARS.contains(&b.to_ascii_lowercase()))
    {
      return Err(ProposalInvalid::NameInvalidChars);
    }

    if self.end_epoch <= self.start_epoch {
      return Err(ProposalInvalid::BadEpochRange);
    }

    if self.payment_amount.is_empty() {
      return Err(ProposalInvalid::BadPaymentAmount);
    }
    let amount_positive = self.payment_amount.parse::<f64>().map(|v| v > 0.0).unwrap_or(false);
    if !amount_positive {
      return Err(ProposalInvalid::BadPaymentAmount);
    }

    if self.url.len() < MIN_URL_LEN {
      return Err(ProposalInvalid::UrlTooShort { len: self.url.len() });
    }
    if self.url.bytes().any(|b| b.is_ascii_whitespace()) {
      return Err(ProposalInvalid::UrlWhitespace);
    }

    Ok(())
  }
}
