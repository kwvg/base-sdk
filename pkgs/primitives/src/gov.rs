//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Governance object and vote types as defined by the Dash protocol.

use crate::error::DecodeError;
use crate::outpoint::OutPoint;
use crate::prelude::*;
use crate::validation::{MAX_PROPOSAL_NAME_LEN, MIN_URL_LEN, PROPOSAL_NAME_CHARS};
use crate::wire;
use crate::TxHash;

use bitcoin_hashes::sha256d;
use hex_conservative::DisplayHex;

use core::fmt;

/// Governance object type codes.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
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
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
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
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
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
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
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
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
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

impl GovObject {
  /// Decodes from the wire format.
  ///
  /// # Errors
  ///
  /// Returns `DecodeError` on malformed input.
  pub fn decode(data: &[u8]) -> Result<Self, DecodeError> {
    let sl = &mut &data[..];
    let hash_parent = wire::read_hash(sl)?.into();
    let revision = wire::read_i32_le(sl)?;
    let time = wire::read_i64_le(sl)?;
    let collateral_hash = wire::read_hash(sl)?.into();
    let obj_data = wire::read_vec(sl, 16_384)?;
    let object_type = GovObjectType::from_i32(wire::read_i32_le(sl)?);
    let mn_hash: TxHash = wire::read_hash(sl)?.into();
    let mn_index = wire::read_u32_le(sl)?;
    let masternode_outpoint = OutPoint {
      hash: mn_hash,
      index: mn_index,
    };
    let sig = wire::read_vec(sl, 1024)?;

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
    crate::script::encode_compact_size(data_hex.len(), &mut buf);
    buf.extend_from_slice(data_hex.as_bytes());
    // outpoint + dummy padding for legacy hash compat
    buf.extend_from_slice(self.masternode_outpoint.hash.as_bytes());
    buf.extend_from_slice(&self.masternode_outpoint.index.to_le_bytes());
    buf.push(0x00);
    buf.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
    // sig with CompactSize prefix
    crate::script::encode_compact_size(self.sig.len(), &mut buf);
    buf.extend_from_slice(&self.sig);

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
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
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

impl GovVote {
  /// Decodes from the wire format.
  ///
  /// # Errors
  ///
  /// Returns `DecodeError` on malformed input.
  pub fn decode(data: &[u8]) -> Result<Self, DecodeError> {
    let sl = &mut &data[..];
    let mn_hash: TxHash = wire::read_hash(sl)?.into();
    let mn_index = wire::read_u32_le(sl)?;
    let masternode_outpoint = OutPoint {
      hash: mn_hash,
      index: mn_index,
    };
    let parent_hash = wire::read_hash(sl)?.into();
    let outcome = wire::read_i32_le(sl)?;
    let signal = wire::read_i32_le(sl)?;
    let time = wire::read_i64_le(sl)?;
    let sig = wire::read_vec(sl, 1024)?;

    Ok(Self {
      masternode_outpoint,
      parent_hash,
      outcome,
      signal,
      time,
      sig,
    })
  }

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
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
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
