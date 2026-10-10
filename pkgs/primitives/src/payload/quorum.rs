//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! LLMQ final commitment payload (type 6).

use super::QuorumHash;
use crate::codec::impl_payload;
use crate::hash_impl;
use crate::support::{DynBitset, LlmqParams, LlmqType};
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

impl Checkable for Commitment {
  type Error = CommitmentInvalid;

  fn check(&self) -> Option<Self::Error> {
    self
      .check_encoding()
      .or_else(|| self.check_type())
      .or_else(|| self.verify())
  }
}

hash_impl!(Commitment);

impl Commitment {
  /// Returns true if this is an indexed commitment (version 2 or 4).
  #[inline]
  pub fn is_indexed(&self) -> bool {
    self.version == 2 || self.version == 4
  }

  /// Tells whether the commitment records a quorum that failed to form, with
  /// no members, keys, signatures or verification vector.
  pub fn is_null(&self) -> bool {
    self.signers.count_ones() == 0
      && self.valid_members.count_ones() == 0
      && self.quorum_public_key.is_null()
      && self.quorum_vvec_hash.is_null()
      && self.members_sig.is_null()
      && self.quorum_sig.is_null()
  }

  fn check_encoding(&self) -> Option<CommitmentInvalid> {
    // Non-canonical BLS fields count as a payload decode failure. A null
    // commitment holds zero bytes, which count as canonical.
    if !(self.quorum_public_key.is_canonical() && self.quorum_sig.is_canonical() && self.members_sig.is_canonical()) {
      return Some(CommitmentInvalid::BadPayload);
    }
    (self.is_indexed() != self.quorum_index.is_some()).then_some(CommitmentInvalid::BadQuorumIndex)
  }

  fn check_type(&self) -> Option<CommitmentInvalid> {
    self
      .llmq_type
      .params()
      .is_none()
      .then_some(CommitmentInvalid::UnknownType {
        llmq_type: self.llmq_type,
      })
  }

  /// Checks what needs no chain: the version range, the bitset sizes, the
  /// member counts against the minimum size, and the presence of the keys,
  /// signatures and verification vector. A null commitment needs only sizes.
  fn verify(&self) -> Option<CommitmentInvalid> {
    let params = self.llmq_type.params()?;
    if self.is_null() {
      return self.verify_sizes(params).map(CommitmentInvalid::InvalidNull);
    }
    let fault = self.verify_non_null(params)?;
    Some(CommitmentInvalid::Invalid(fault))
  }

  fn verify_sizes(&self, params: LlmqParams) -> Option<CommitmentFault> {
    let size = u64::from(params.size);
    if self.signers.num_bits != size {
      return Some(CommitmentFault::SignersSize {
        size: self.signers.num_bits,
      });
    }
    if self.valid_members.num_bits != size {
      return Some(CommitmentFault::ValidMembersSize {
        size: self.valid_members.num_bits,
      });
    }
    None
  }

  fn verify_non_null(&self, params: LlmqParams) -> Option<CommitmentFault> {
    // The exact version depends on the chain; any version a commitment can
    // carry passes here.
    if !(1..=4).contains(&self.version) {
      return Some(CommitmentFault::Version { version: self.version });
    }
    if let Some(fault) = self.verify_sizes(params) {
      return Some(fault);
    }
    let min_size = u64::from(params.min_size);
    let valid_members = self.valid_members.count_ones();
    if valid_members < min_size {
      return Some(CommitmentFault::ValidMembersCount { count: valid_members });
    }
    let signers = self.signers.count_ones();
    if signers < min_size {
      return Some(CommitmentFault::SignersCount { count: signers });
    }
    // A canonical point is valid unless it is null.
    if self.quorum_public_key.is_null() {
      return Some(CommitmentFault::QuorumPublicKey);
    }
    if params.size > 1 && self.quorum_vvec_hash.is_null() {
      return Some(CommitmentFault::QuorumVvecHash);
    }
    if self.members_sig.is_null() {
      return Some(CommitmentFault::MembersSig);
    }
    if self.quorum_sig.is_null() {
      return Some(CommitmentFault::QuorumSig);
    }
    None
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
  /// `bad-qc-payload`
  BadPayload,
  /// `bad-qc-commitment-type`
  UnknownType { llmq_type: LlmqType },
  /// `bad-qc-version`
  BadVersion { version: u16 },
  /// `bad-qc-invalid-null`
  InvalidNull(CommitmentFault),
  /// `bad-qc-invalid`
  Invalid(CommitmentFault),
}

impl fmt::Display for CommitmentInvalid {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    match self {
      Self::BadQuorumIndex => write!(f, "bad-qc-quorum-index"),
      Self::BadPayload => write!(f, "bad-qc-payload"),
      Self::UnknownType { llmq_type } => write!(f, "bad-qc-commitment-type: {llmq_type}"),
      Self::BadVersion { version } => write!(f, "bad-qc-version: {version}"),
      Self::InvalidNull(fault) => write!(f, "bad-qc-invalid-null: {fault}"),
      Self::Invalid(fault) => write!(f, "bad-qc-invalid: {fault}"),
    }
  }
}

/// The part of a commitment that fails its context-free verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Unencodable)]
pub enum CommitmentFault {
  /// The version is not one a commitment can carry.
  Version { version: u16 },
  /// The signers bitset is not the quorum size.
  SignersSize { size: u64 },
  /// The valid-members bitset is not the quorum size.
  ValidMembersSize { size: u64 },
  /// Fewer valid members than the quorum's minimum size.
  ValidMembersCount { count: u64 },
  /// Fewer signers than the quorum's minimum size.
  SignersCount { count: u64 },
  /// The quorum public key is null.
  QuorumPublicKey,
  /// The verification vector hash is null.
  QuorumVvecHash,
  /// The aggregated members signature is null.
  MembersSig,
  /// The quorum signature is null.
  QuorumSig,
}

impl fmt::Display for CommitmentFault {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    match self {
      Self::Version { version } => write!(f, "version {version}"),
      Self::SignersSize { size } => write!(f, "signers size {size}"),
      Self::ValidMembersSize { size } => write!(f, "valid members size {size}"),
      Self::ValidMembersCount { count } => write!(f, "valid members count {count}"),
      Self::SignersCount { count } => write!(f, "signers count {count}"),
      Self::QuorumPublicKey => write!(f, "null quorum public key"),
      Self::QuorumVvecHash => write!(f, "null verification vector hash"),
      Self::MembersSig => write!(f, "null members signature"),
      Self::QuorumSig => write!(f, "null quorum signature"),
    }
  }
}

impl Checkable for FinalCommitment {
  type Error = CommitmentInvalid;

  fn check(&self) -> Option<Self::Error> {
    let qc = &self.commitment;
    qc.check_encoding()
      .or_else(|| qc.check_type())
      .or_else(|| {
        (self.version != Self::CURRENT_VERSION).then_some(CommitmentInvalid::BadVersion { version: self.version })
      })
      .or_else(|| qc.verify())
  }
}

hash_impl!(FinalCommitment);

impl FinalCommitment {
  /// The only payload version.
  pub const CURRENT_VERSION: u16 = 1;
}

impl fmt::Display for FinalCommitment {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "FinalCommitment {{ v{}, height: {} }}", self.version, self.height,)
  }
}

#[cfg(all(test, feature = "serde"))]
#[expect(clippy::panic, clippy::unwrap_used, reason = "test code")]
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

  #[rstest]
  #[case::quorum_public_key(|qc: &mut Commitment| qc.quorum_public_key = qc.quorum_public_key.corrupted())]
  #[case::quorum_sig(|qc: &mut Commitment| qc.quorum_sig = qc.quorum_sig.corrupted())]
  #[case::members_sig(|qc: &mut Commitment| qc.members_sig = qc.members_sig.corrupted())]
  fn non_canonical_bls_field_is_a_bad_payload(#[case] corrupt: fn(&mut Commitment)) {
    let corpus = Corpus::open(env!("CARGO_MANIFEST_DIR"), "qctx");
    let mut item = corpus
      .entries::<FinalCommitment>("qctx", |_, _, _| {})
      .into_values()
      .next()
      .unwrap();
    assert_eq!(item.check(), None);
    corrupt(&mut item.commitment);
    assert_eq!(item.check(), Some(CommitmentInvalid::BadPayload));
    assert_eq!(CommitmentInvalid::BadPayload.to_string(), "bad-qc-payload");
  }

  /// Null BLS fields pass the encoding check and fail verification as missing.
  #[rstest]
  fn null_bls_fields_pass_the_encoding_check() {
    let corpus = Corpus::open(env!("CARGO_MANIFEST_DIR"), "qctx");
    let mut item = corpus
      .entries::<FinalCommitment>("qctx", |_, _, _| {})
      .into_values()
      .next()
      .unwrap();
    let qc = &mut item.commitment;
    qc.quorum_public_key = BlsPubKey::from_bytes([0; BLS_PK_LEN], BlsScheme::Basic);
    qc.quorum_sig = BlsSig::from_bytes([0; BLS_SIG_LEN], BlsScheme::Basic);
    qc.members_sig = BlsSig::from_bytes([0; BLS_SIG_LEN], BlsScheme::Basic);
    assert_eq!(
      item.check(),
      Some(CommitmentInvalid::Invalid(CommitmentFault::QuorumPublicKey))
    );
  }

  fn corpus_commitment() -> Commitment {
    let corpus = Corpus::open(env!("CARGO_MANIFEST_DIR"), "qctx");
    corpus
      .entries::<FinalCommitment>("qctx", |_, _, _| {})
      .into_values()
      .map(|item| item.commitment)
      .find(|qc| !qc.is_null())
      .unwrap()
  }

  /// Builds a bitset of `num_bits` bits with the lowest `ones` set.
  fn bitset(num_bits: u64, ones: u64) -> DynBitset {
    let mut data = vec![0u8; (num_bits as usize).div_ceil(8)];
    for i in 0..ones as usize {
      data[i / 8] |= 1 << (i % 8);
    }
    DynBitset { num_bits, data }
  }

  fn null_commitment() -> Commitment {
    let mut qc = corpus_commitment();
    let size = u64::from(qc.llmq_type.params().unwrap().size);
    let scheme = qc.quorum_public_key.scheme();
    qc.signers = bitset(size, 0);
    qc.valid_members = bitset(size, 0);
    qc.quorum_public_key = BlsPubKey::from_bytes([0; BLS_PK_LEN], scheme);
    qc.quorum_vvec_hash = QuorumVvecHash::default();
    qc.members_sig = BlsSig::from_bytes([0; BLS_SIG_LEN], scheme);
    qc.quorum_sig = BlsSig::from_bytes([0; BLS_SIG_LEN], scheme);
    qc
  }

  #[rstest]
  fn corpus_commitments_verify() {
    let corpus = Corpus::open(env!("CARGO_MANIFEST_DIR"), "qctx");
    let mut nulls = BTreeSet::new();
    for (label, item) in corpus.entries::<FinalCommitment>("qctx", |_, _, _| {}) {
      assert_eq!(item.commitment.check(), None, "{label}");
      nulls.insert(item.commitment.is_null());
    }
    assert_eq!(nulls.len(), 2, "the corpus holds null and non-null commitments");
  }

  #[rstest]
  #[case::none(LlmqType::LlmqNone)]
  #[case::unknown(LlmqType::Unknown(7))]
  fn type_without_params_is_unknown(#[case] llmq_type: LlmqType) {
    let mut qc = corpus_commitment();
    qc.llmq_type = llmq_type;
    assert_eq!(qc.check(), Some(CommitmentInvalid::UnknownType { llmq_type }));
    assert_eq!(
      qc.check().unwrap().to_string(),
      format!("bad-qc-commitment-type: {llmq_type}")
    );
  }

  /// A null commitment needs only the right bitset sizes, whatever its
  /// version.
  #[rstest]
  fn null_commitment_needs_only_sizes() {
    let qc = null_commitment();
    assert!(qc.is_null());
    assert_eq!(qc.check(), None);

    let mut wrong = qc.clone();
    wrong.signers = bitset(qc.signers.num_bits + 1, 0);
    assert_eq!(
      wrong.check(),
      Some(CommitmentInvalid::InvalidNull(CommitmentFault::SignersSize {
        size: qc.signers.num_bits + 1
      }))
    );
    assert!(wrong.check().unwrap().to_string().starts_with("bad-qc-invalid-null: "));
  }

  #[rstest]
  #[case::version(|qc: &mut Commitment| qc.version = 5, CommitmentFault::Version { version: 5 })]
  #[case::signers_size(|qc: &mut Commitment| qc.signers = bitset(qc.signers.num_bits - 1, 1), CommitmentFault::SignersSize { size: 0 })]
  #[case::valid_members_size(|qc: &mut Commitment| qc.valid_members = bitset(qc.valid_members.num_bits + 1, 1), CommitmentFault::ValidMembersSize { size: 0 })]
  #[case::valid_members_count(|qc: &mut Commitment| qc.valid_members = bitset(qc.valid_members.num_bits, min_size(qc) - 1), CommitmentFault::ValidMembersCount { count: 0 })]
  #[case::signers_count(|qc: &mut Commitment| qc.signers = bitset(qc.signers.num_bits, min_size(qc) - 1), CommitmentFault::SignersCount { count: 0 })]
  #[case::quorum_public_key(|qc: &mut Commitment| qc.quorum_public_key = BlsPubKey::from_bytes([0; BLS_PK_LEN], BlsScheme::Basic), CommitmentFault::QuorumPublicKey)]
  #[case::quorum_vvec_hash(|qc: &mut Commitment| qc.quorum_vvec_hash = QuorumVvecHash::default(), CommitmentFault::QuorumVvecHash)]
  #[case::members_sig(|qc: &mut Commitment| qc.members_sig = BlsSig::from_bytes([0; BLS_SIG_LEN], BlsScheme::Basic), CommitmentFault::MembersSig)]
  #[case::quorum_sig(|qc: &mut Commitment| qc.quorum_sig = BlsSig::from_bytes([0; BLS_SIG_LEN], BlsScheme::Basic), CommitmentFault::QuorumSig)]
  fn non_null_commitment_faults(#[case] edit: fn(&mut Commitment), #[case] fault: CommitmentFault) {
    let mut qc = corpus_commitment();
    edit(&mut qc);
    let Some(CommitmentInvalid::Invalid(found)) = qc.check() else {
      panic!("{:?}", qc.check());
    };
    assert_eq!(core::mem::discriminant(&found), core::mem::discriminant(&fault));
    assert!(CommitmentInvalid::Invalid(found)
      .to_string()
      .starts_with("bad-qc-invalid: "));
  }

  fn min_size(qc: &Commitment) -> u64 {
    u64::from(qc.llmq_type.params().unwrap().min_size)
  }

  #[rstest]
  #[case::zero(0)]
  #[case::two(2)]
  fn payload_version_other_than_one_is_rejected(#[case] version: u16) {
    let corpus = Corpus::open(env!("CARGO_MANIFEST_DIR"), "qctx");
    let mut item = corpus
      .entries::<FinalCommitment>("qctx", |_, _, _| {})
      .into_values()
      .next()
      .unwrap();
    assert_eq!(item.version, FinalCommitment::CURRENT_VERSION);
    item.version = version;
    assert_eq!(item.check(), Some(CommitmentInvalid::BadVersion { version }));
    assert_eq!(item.check().unwrap().to_string(), format!("bad-qc-version: {version}"));

    // The payload version is checked after the encoding and the type.
    item.commitment.llmq_type = LlmqType::LlmqNone;
    assert!(matches!(item.check(), Some(CommitmentInvalid::UnknownType { .. })));
    item.commitment.quorum_sig = item.commitment.quorum_sig.corrupted();
    assert_eq!(item.check(), Some(CommitmentInvalid::BadPayload));
  }

  /// The counts compare with the minimum size, not the threshold.
  #[rstest]
  fn counts_at_the_minimum_size_pass() {
    let mut qc = corpus_commitment();
    let params = qc.llmq_type.params().unwrap();
    assert!(params.min_size > params.threshold);
    qc.valid_members = bitset(qc.valid_members.num_bits, u64::from(params.min_size));
    qc.signers = bitset(qc.signers.num_bits, u64::from(params.min_size));
    assert_eq!(qc.check(), None);
  }
}
