//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! LLMQ final commitment payload (type 6).

use super::QuorumHash;
use crate::codec::impl_payload;
use crate::hash_impl;
use crate::support::{DynBitset, LlmqType};
use crate::types::{BlsPubKey, BlsScheme, BlsSig};

use dash_num::make_hash;
#[cfg(feature = "serde")]
use dash_pkc::bls::{BLS_PK_LEN, BLS_SIG_LEN};
use dash_types::codec::{BaseCodec, DecodeError, EncodeBuf};
use dash_types::type_id::{TypeId, Unencodable};
use dash_types::{Checkable, Numeric};

use core::fmt;

make_hash! {
  /// Quorum verification vector hash.
  QuorumVvecHash, 32
}

hash_impl!(QuorumVvecHash);

/// DKG session output for one LLMQ.
///
/// - v1: legacy
/// - v2: legacy + indexed (quorum_index)
/// - v3: basic
/// - v4: basic + indexed (quorum_index)
#[derive(Clone, Debug, Eq, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase", from = "__CommitmentFields"))]
pub struct Commitment {
  /// 1=legacy, 2=+indexed, 3=basic, 4=basic+idx.
  pub version: u16,
  /// LLMQ type.
  pub llmq_type: LlmqType,
  /// Quorum block hash.
  pub quorum_hash: QuorumHash,
  /// Present for indexed versions (2, 4).
  pub quorum_index: Option<i16>,
  /// Signers bitset.
  pub signers: DynBitset,
  /// Valid members bitset.
  pub valid_members: DynBitset,
  /// Quorum BLS public key (48 bytes).
  pub quorum_public_key: BlsPubKey,
  /// Quorum verification vector hash (32 bytes).
  pub quorum_vvec_hash: QuorumVvecHash,
  /// Threshold signature over commitment.
  pub quorum_sig: BlsSig,
  /// Aggregated per-member signature.
  pub members_sig: BlsSig,
}

impl_payload!(Commitment);

impl BaseCodec for Commitment {
  fn decode(data: &mut &[u8]) -> Result<Self, DecodeError> {
    let version = u16::decode(data)?;
    let llmq_type = LlmqType::from_base(u8::decode(data)?);
    let quorum_hash = QuorumHash::decode(data)?;
    let quorum_index = if version == 2 || version == 4 {
      Some(i16::decode(data)?)
    } else {
      None
    };
    let scheme = BlsScheme::from_commitment_version(version);

    Ok(Self {
      version,
      llmq_type,
      quorum_hash,
      quorum_index,
      signers: DynBitset::decode(data)?,
      valid_members: DynBitset::decode(data)?,
      quorum_public_key: BlsPubKey::decode(data, scheme)?,
      quorum_vvec_hash: QuorumVvecHash::decode(data)?,
      quorum_sig: BlsSig::decode(data, scheme)?,
      members_sig: BlsSig::decode(data, scheme)?,
    })
  }

  fn encode(&self, buf: &mut impl EncodeBuf) {
    self.version.encode(buf);
    self.llmq_type.to_base().encode(buf);
    self.quorum_hash.encode(buf);
    if let Some(idx) = self.quorum_index {
      idx.encode(buf);
    }
    self.signers.encode(buf);
    self.valid_members.encode(buf);
    self.quorum_public_key.encode(buf);
    self.quorum_vvec_hash.encode(buf);
    self.quorum_sig.encode(buf);
    self.members_sig.encode(buf);
  }
}

hash_impl!(Commitment);

impl Commitment {
  /// Returns true if this is an indexed commitment (version 2 or 4).
  #[inline]
  pub fn is_indexed(&self) -> bool {
    self.version == 2 || self.version == 4
  }
}

/// Field set that tags the BLS fields from the commitment version.
#[cfg(feature = "serde")]
#[derive(::serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct __CommitmentFields {
  version: u16,
  llmq_type: LlmqType,
  quorum_hash: QuorumHash,
  quorum_index: Option<i16>,
  signers: DynBitset,
  valid_members: DynBitset,
  #[serde(deserialize_with = "crate::serialize::bls::pk_bytes")]
  quorum_public_key: [u8; BLS_PK_LEN],
  quorum_vvec_hash: QuorumVvecHash,
  #[serde(deserialize_with = "crate::serialize::bls::sig_bytes")]
  quorum_sig: [u8; BLS_SIG_LEN],
  #[serde(deserialize_with = "crate::serialize::bls::sig_bytes")]
  members_sig: [u8; BLS_SIG_LEN],
}

#[cfg(feature = "serde")]
impl From<__CommitmentFields> for Commitment {
  fn from(fields: __CommitmentFields) -> Self {
    let scheme = BlsScheme::from_commitment_version(fields.version);
    Self {
      version: fields.version,
      llmq_type: fields.llmq_type,
      quorum_hash: fields.quorum_hash,
      quorum_index: fields.quorum_index,
      signers: fields.signers,
      valid_members: fields.valid_members,
      quorum_public_key: BlsPubKey::from_bytes(fields.quorum_public_key, scheme),
      quorum_vvec_hash: fields.quorum_vvec_hash,
      quorum_sig: BlsSig::from_bytes(fields.quorum_sig, scheme),
      members_sig: BlsSig::from_bytes(fields.members_sig, scheme),
    }
  }
}

impl fmt::Display for Commitment {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "Commitment {{ v{}, llmq: {} }}", self.version, self.llmq_type,)
  }
}

/// Tx-level wrapper for Commitment (type 6).
#[derive(Clone, Debug, Eq, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub struct FinalCommitment {
  /// Payload version.
  pub version: u16,
  /// Block height.
  pub height: bitcoin_units::BlockHeight,
  /// The commitment itself.
  pub commitment: Commitment,
}

impl_payload!(FinalCommitment);

impl BaseCodec for FinalCommitment {
  fn decode(data: &mut &[u8]) -> Result<Self, DecodeError> {
    Ok(Self {
      version: u16::decode(data)?,
      height: bitcoin_units::BlockHeight::from_u32(u32::decode(data)?),
      commitment: Commitment::decode(data)?,
    })
  }

  fn encode(&self, buf: &mut impl EncodeBuf) {
    self.version.encode(buf);
    self.height.to_u32().encode(buf);
    self.commitment.encode(buf);
  }
}

/// Final commitment validation failure.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Unencodable)]
pub enum CommitmentInvalid {
  /// `bad-qc-quorum-index`
  BadQuorumIndex,
}

impl fmt::Display for CommitmentInvalid {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    match self {
      Self::BadQuorumIndex => write!(f, "bad-qc-quorum-index"),
    }
  }
}

impl Checkable for FinalCommitment {
  type Error = CommitmentInvalid;

  fn check(&self) -> Option<Self::Error> {
    let indexed = self.commitment.version == 2 || self.commitment.version == 4;
    if indexed != self.commitment.quorum_index.is_some() {
      return Some(CommitmentInvalid::BadQuorumIndex);
    }
    None
  }
}

hash_impl!(FinalCommitment);

impl fmt::Display for FinalCommitment {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "FinalCommitment {{ v{}, height: {} }}", self.version, self.height,)
  }
}

#[cfg(all(test, feature = "serde"))]
#[expect(clippy::unwrap_used, reason = "test code")]
mod tests {
  use super::*;
  use crate::prelude::*;

  use dash_dev::{assert_serde_rt, check_sptx, from_json, to_json, Corpus};
  use rstest::rstest;

  #[rstest]
  fn corpus_qctx() {
    let corpus = Corpus::open(env!("CARGO_MANIFEST_DIR"), "qctx");
    let items = corpus.entries::<FinalCommitment>("qctx", check_sptx);
    assert_serde_rt("qctx", &items);
  }

  /// Version 3 shares a layout with version 1, and version 4 with version 2,
  /// so a version 3 corpus commitment serves for all four.
  #[rstest]
  #[case::v1(1, BlsScheme::Legacy)]
  #[case::v2(2, BlsScheme::Legacy)]
  #[case::v3(3, BlsScheme::Basic)]
  #[case::v4(4, BlsScheme::Basic)]
  fn bls_fields_are_tagged_from_the_version(#[case] version: u16, #[case] scheme: BlsScheme) {
    let corpus = Corpus::open(env!("CARGO_MANIFEST_DIR"), "qctx");
    let mut item = corpus
      .entries::<FinalCommitment>("qctx", |_, _, _| {})
      .into_values()
      .next()
      .unwrap();
    let qc = &mut item.commitment;
    assert_eq!(qc.version, 3);
    qc.version = version;
    qc.quorum_index = matches!(version, 2 | 4).then_some(0);
    qc.quorum_public_key = BlsPubKey::from_bytes(*qc.quorum_public_key.as_bytes(), scheme);
    qc.quorum_sig = BlsSig::from_bytes(*qc.quorum_sig.as_bytes(), scheme);
    qc.members_sig = BlsSig::from_bytes(*qc.members_sig.as_bytes(), scheme);

    let mut buf = Vec::new();
    item.encode(&mut buf);
    let decoded = FinalCommitment::decode(&mut buf.as_slice()).unwrap();
    let schemes = |qc: &Commitment| {
      (
        qc.quorum_public_key.scheme(),
        qc.quorum_sig.scheme(),
        qc.members_sig.scheme(),
      )
    };
    assert_eq!(schemes(&decoded.commitment), (scheme, scheme, scheme));
    assert_eq!(decoded, item);
    assert_eq!(from_json::<FinalCommitment>(&to_json(&item)), item);
  }
}
