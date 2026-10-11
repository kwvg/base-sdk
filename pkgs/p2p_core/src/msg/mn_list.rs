//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Simplified masternode list.

use crate::codec::{codec_p2p, impl_p2p};
use crate::macros::VersionedPayload;
use crate::prelude::*;
use crate::{P2pDecodeError, ProtocolVersion};

use bitcoin_hashes::sha256d;
use dash_num::Hash256;
use dash_pkc::bls::{BlsScIetf, BlsSigBytes, BLS_PK_LEN};
use dash_primitives::{
  hash_impl, merkle_root_mutated, BlockHash, BlsPubKey, BlsScheme, Commitment, LlmqType, MerkleRoot, MnType, NetInfo,
  NetInfoV1, NetInfoV2, PartialMerkleTree, PlatformNodeId, Transaction, TxHash, PROTX_VERSION_BASIC_BLS,
  PROTX_VERSION_EXT_ADDR, PROTX_VERSION_LEGACY_BLS,
};
use dash_script::PubKeyHash;
use dash_types::codec::{BaseCodec, DecodeError, EncodeBuf};
use dash_types::type_id::{TypeId, Unencodable};
use dash_types::{Checkable, CompactSize, Hashable, Numeric};

use core::fmt;

/// Deleted quorum identifier (type + hash).
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub struct DeletedQuorum {
  /// LLMQ type.
  pub llmq_type: LlmqType,
  /// Quorum hash.
  pub hash: BlockHash,
}

codec_p2p!(DeletedQuorum { llmq_type, hash });

/// Requests a masternode list diff between two blocks.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct GetMnListDiff {
  /// Base block hash (beginning of range).
  pub base_block_hash: BlockHash,
  /// Target block hash (end of range).
  pub block_hash: BlockHash,
}

codec_p2p!(GetMnListDiff {
  base_block_hash,
  block_hash
});

/// Response carrying the masternode list diff.
#[derive(Clone, Debug, Eq, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct MnListDiff {
  /// The full diff payload.
  pub payload: MnListDiffPayload,
}

codec_p2p!(MnListDiff { payload });

impl VersionedPayload for MnListDiff {
  fn decode_versioned(payload: &[u8], version: ProtocolVersion) -> Result<Self, P2pDecodeError> {
    let mut data = payload;
    let payload = MnListDiffPayload::decode_versioned(&mut data, version)?;
    if !data.is_empty() {
      return Err(DecodeError::TrailingBytes { remaining: data.len() }.into());
    }
    Ok(Self { payload })
  }

  fn encode_versioned(&self, buf: &mut Vec<u8>, version: ProtocolVersion) {
    self.payload.encode_versioned(buf, version);
  }
}

/// Masternode list diff failure.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Unencodable)]
pub enum MnListDiffInvalid {
  /// The entry at `index` of `mn_list` fails its check.
  Entry { index: usize, error: SmlEntryInvalid },
  /// Two chainlock signatures are equal, which a signature-keyed map cannot
  /// hold.
  DuplicateClSig,
  /// A chainlock index set is not strictly ascending.
  UnsortedClSigIndices,
  /// A chainlock index points past `new_quorums`.
  ClSigIndexOutOfRange { index: u16 },
}

impl fmt::Display for MnListDiffInvalid {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    match self {
      Self::Entry { index, error } => write!(f, "mnlistdiff entry {index}: {error}"),
      Self::DuplicateClSig => f.write_str("mnlistdiff repeats a chainlock signature"),
      Self::UnsortedClSigIndices => f.write_str("mnlistdiff chainlock indices not strictly ascending"),
      Self::ClSigIndexOutOfRange { index } => write!(f, "mnlistdiff chainlock index {index} past the new quorums"),
    }
  }
}

/// Full masternode list diff payload.
#[derive(Clone, Debug, Eq, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub struct MnListDiffPayload {
  /// Serialisation version.
  pub version: u16,
  /// Base block hash (start of the diff range).
  pub base_block_hash: BlockHash,
  /// Target block hash (end of the diff range).
  pub block_hash: BlockHash,
  /// Proof of the coinbase transaction against the target block.
  pub cb_tx_merkle_tree: PartialMerkleTree,
  /// Coinbase transaction (carries the MN list commitment).
  pub cb_tx: Transaction,
  /// ProTxHashes of removed masternodes.
  pub deleted_mns: Vec<TxHash>,
  /// New or updated masternode entries.
  pub mn_list: Vec<SimplifiedMnListEntry>,
  /// Removed quorums.
  pub deleted_quorums: Vec<DeletedQuorum>,
  /// New quorum final commitments.
  pub new_quorums: Vec<Commitment>,
  /// Chainlock signature mappings.
  pub quorum_cl_sigs: Vec<QuorumClSig>,
}

impl_p2p!(MnListDiffPayload);

impl BaseCodec for MnListDiffPayload {
  fn decode(data: &mut &[u8]) -> Result<Self, DecodeError> {
    Self::decode_versioned(data, ProtocolVersion::CURRENT)
  }

  fn encode(&self, buf: &mut impl EncodeBuf) {
    self.encode_versioned(buf, ProtocolVersion::CURRENT);
  }
}

impl Checkable for MnListDiffPayload {
  type Error = MnListDiffInvalid;

  fn check(&self) -> Option<Self::Error> {
    for (index, entry) in self.mn_list.iter().enumerate() {
      if let Some(error) = entry.check() {
        return Some(MnListDiffInvalid::Entry { index, error });
      }
    }
    for (i, cl_sig) in self.quorum_cl_sigs.iter().enumerate() {
      if self.quorum_cl_sigs[..i].iter().any(|other| other.sig == cl_sig.sig) {
        return Some(MnListDiffInvalid::DuplicateClSig);
      }
      if cl_sig.index_set.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Some(MnListDiffInvalid::UnsortedClSigIndices);
      }
      if let Some(&index) = cl_sig
        .index_set
        .iter()
        .find(|&&index| usize::from(index) >= self.new_quorums.len())
      {
        return Some(MnListDiffInvalid::ClSigIndexOutOfRange { index });
      }
    }
    None
  }
}

hash_impl!(MnListDiffPayload);

impl MnListDiffPayload {
  /// Reads the diff as sent at protocol `version`. The serialisation version
  /// is 1 where `version` leaves it off the wire.
  ///
  /// # Errors
  ///
  /// Returns [`DecodeError`] on malformed input.
  pub fn decode_versioned(data: &mut &[u8], version: ProtocolVersion) -> Result<Self, DecodeError> {
    let mut diff_version = 1;
    if version >= ProtocolVersion::MNLISTDIFF_VERSION_ORDER {
      diff_version = u16::decode(data)?;
    }
    let base_block_hash = BlockHash::decode(data)?;
    let block_hash = BlockHash::decode(data)?;
    let cb_tx_merkle_tree = PartialMerkleTree::decode(data)?;
    let cb_tx = Transaction::decode(data)?;
    if (ProtocolVersion::BLS_SCHEME..ProtocolVersion::MNLISTDIFF_VERSION_ORDER).contains(&version) {
      diff_version = u16::decode(data)?;
    }
    let deleted_mns = Vec::decode(data)?;
    let mut mn_list = Vec::new();
    for _ in 0..CompactSize::decode_len(data)? {
      mn_list.push(SimplifiedMnListEntry::decode_versioned(data, version)?);
    }
    let deleted_quorums = Vec::decode(data)?;
    let new_quorums = Vec::decode(data)?;
    let quorum_cl_sigs = if version >= ProtocolVersion::MNLISTDIFF_CHAINLOCKS {
      Vec::decode(data)?
    } else {
      Vec::new()
    };
    Ok(Self {
      version: diff_version,
      base_block_hash,
      block_hash,
      cb_tx_merkle_tree,
      cb_tx,
      deleted_mns,
      mn_list,
      deleted_quorums,
      new_quorums,
      quorum_cl_sigs,
    })
  }

  /// Writes the diff as sent at protocol `version`. Fields that `version`
  /// leaves off the wire are dropped.
  pub fn encode_versioned(&self, buf: &mut impl EncodeBuf, version: ProtocolVersion) {
    if version >= ProtocolVersion::MNLISTDIFF_VERSION_ORDER {
      self.version.encode(buf);
    }
    self.base_block_hash.encode(buf);
    self.block_hash.encode(buf);
    self.cb_tx_merkle_tree.encode(buf);
    self.cb_tx.encode(buf);
    if (ProtocolVersion::BLS_SCHEME..ProtocolVersion::MNLISTDIFF_VERSION_ORDER).contains(&version) {
      self.version.encode(buf);
    }
    self.deleted_mns.encode(buf);
    CompactSize::from(self.mn_list.len()).encode(buf);
    for entry in &self.mn_list {
      entry.encode_versioned(buf, version);
    }
    self.deleted_quorums.encode(buf);
    self.new_quorums.encode(buf);
    if version >= ProtocolVersion::MNLISTDIFF_CHAINLOCKS {
      self.quorum_cl_sigs.encode(buf);
    }
  }
}

impl fmt::Display for MnListDiffPayload {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(
      f,
      "mnlistdiff v{}: {}..{} ({} MNs, {} deleted)",
      self.version,
      self.base_block_hash,
      self.block_hash,
      self.mn_list.len(),
      self.deleted_mns.len(),
    )
  }
}

/// Chainlock signature entry in the MN list diff.
///
/// Each entry maps a BLS signature to the indices (within
/// `new_quorums`) of the quorums it covers.
#[derive(Clone, Debug, Eq, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub struct QuorumClSig {
  /// BLS signature.
  pub sig: BlsSigBytes<BlsScIetf>,
  /// Indices into the `new_quorums` vector.
  pub index_set: Vec<u16>,
}

codec_p2p!(QuorumClSig { sig, index_set });

/// Simplified masternode list entry failure.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Unencodable)]
pub enum SmlEntryInvalid {
  /// The version is outside the ProTx versions.
  BadVersion { version: u16 },
  /// A version 1 entry has a type other than regular, which version 1
  /// cannot encode.
  TypeBeforeBasicBls { mn_type: MnType },
  /// The platform fields present do not match the type and version.
  BadPlatformFields,
}

impl fmt::Display for SmlEntryInvalid {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    match self {
      Self::BadVersion { version } => write!(f, "sml entry version {version} out of range"),
      Self::TypeBeforeBasicBls { mn_type } => {
        write!(f, "sml entry type {} below the basic bls version", mn_type.to_base())
      }
      Self::BadPlatformFields => f.write_str("sml entry platform fields do not match its type and version"),
    }
  }
}

/// The net info form of a simplified masternode list entry disagrees with
/// its version.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Unencodable)]
pub struct NetInfoVersionMismatch;

impl fmt::Display for NetInfoVersionMismatch {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.write_str("net info form does not match the entry version")
  }
}

/// A single entry in the simplified masternode list.
///
/// The version-coupled fields are private, so [`SimplifiedMnListEntry::new`]
/// keeps the net info form and the operator key scheme in step with the
/// version.
#[derive(Clone, Debug, Eq, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase", try_from = "__SmlEntryFields"))]
pub struct SimplifiedMnListEntry {
  version: u16,
  /// Masternode registration transaction hash.
  pub pro_reg_tx_hash: TxHash,
  /// Block hash at confirmation depth.
  pub confirmed_hash: BlockHash,
  net_info: NetInfo,
  operator_key: BlsPubKey,
  /// Voting key hash (HASH160).
  pub voting_key_id: PubKeyHash,
  /// Whether this masternode is currently valid.
  pub is_valid: bool,
  /// Masternode type (Regular or Evo).
  pub mn_type: MnType,
  /// Platform HTTP port, carried by evo masternodes below version 3.
  #[cfg_attr(feature = "serde", serde(rename = "platformHTTPPort"))]
  pub platform_http_port: Option<u16>,
  /// Platform node ID (Evo masternodes only).
  pub platform_node_id: Option<PlatformNodeId>,
}

impl_p2p!(SimplifiedMnListEntry);

impl BaseCodec for SimplifiedMnListEntry {
  fn decode(data: &mut &[u8]) -> Result<Self, DecodeError> {
    Self::decode_versioned(data, ProtocolVersion::CURRENT)
  }

  fn encode(&self, buf: &mut impl EncodeBuf) {
    self.encode_versioned(buf, ProtocolVersion::CURRENT);
  }
}

/// The checks cover what the entry version can encode. Net info is not
/// validated, since revoked masternodes carry empty net info.
impl Checkable for SimplifiedMnListEntry {
  type Error = SmlEntryInvalid;

  fn check(&self) -> Option<Self::Error> {
    if !(PROTX_VERSION_LEGACY_BLS..=PROTX_VERSION_EXT_ADDR).contains(&self.version) {
      return Some(SmlEntryInvalid::BadVersion { version: self.version });
    }
    if self.version < PROTX_VERSION_BASIC_BLS && self.mn_type != MnType::Regular {
      return Some(SmlEntryInvalid::TypeBeforeBasicBls { mn_type: self.mn_type });
    }
    let is_evo = self.mn_type == MnType::Evo;
    let has_http_port = is_evo && self.version < PROTX_VERSION_EXT_ADDR;
    if self.platform_http_port.is_some() != has_http_port || self.platform_node_id.is_some() != is_evo {
      return Some(SmlEntryInvalid::BadPlatformFields);
    }
    None
  }
}

/// The hash leaves out the entry version and keeps the fields that the
/// version carries.
impl Hashable for SimplifiedMnListEntry {
  type Hash = Hash256;

  fn hash(&self) -> Hash256 {
    let mut buf = Vec::new();
    self.encode_fields(&mut buf, true);
    Hash256::from_lendian(sha256d::Hash::hash(&buf).to_byte_array())
  }
}

impl SimplifiedMnListEntry {
  /// Reads the entry as sent at protocol `version`. The entry version is 1
  /// where `version` leaves it off the wire.
  ///
  /// # Errors
  ///
  /// Returns [`DecodeError`] on malformed input.
  pub fn decode_versioned(data: &mut &[u8], version: ProtocolVersion) -> Result<Self, DecodeError> {
    let entry_version = if version >= ProtocolVersion::SMNLE_VERSIONED {
      u16::decode(data)?
    } else {
      1
    };
    let pro_reg_tx_hash = TxHash::decode(data)?;
    let confirmed_hash = BlockHash::decode(data)?;
    let net_info = if entry_version >= PROTX_VERSION_EXT_ADDR {
      NetInfo::Extended(NetInfoV2::decode(data)?)
    } else {
      NetInfo::Legacy(NetInfoV1::decode(data)?)
    };
    let operator_key = BlsPubKey::decode(data, BlsScheme::from_protx_version(entry_version))?;
    let voting_key_id = PubKeyHash::decode(data)?;
    let is_valid = bool::decode(data)?;

    let mn_type = if version >= ProtocolVersion::DMN_TYPE && entry_version >= 2 {
      MnType::from_base(u16::decode(data)?)
    } else {
      MnType::Regular
    };

    let (platform_http_port, platform_node_id) = if mn_type == MnType::Evo {
      let http_port = if entry_version < PROTX_VERSION_EXT_ADDR {
        Some(u16::decode(data)?)
      } else {
        None
      };
      (http_port, Some(PlatformNodeId::decode(data)?))
    } else {
      (None, None)
    };

    Ok(Self {
      version: entry_version,
      pro_reg_tx_hash,
      confirmed_hash,
      net_info,
      operator_key,
      voting_key_id,
      is_valid,
      mn_type,
      platform_http_port,
      platform_node_id,
    })
  }

  /// Writes the entry as sent at protocol `version`. Fields that `version`
  /// leaves off the wire are dropped.
  pub fn encode_versioned(&self, buf: &mut impl EncodeBuf, version: ProtocolVersion) {
    if version >= ProtocolVersion::SMNLE_VERSIONED {
      self.version.encode(buf);
    }
    self.encode_fields(buf, version >= ProtocolVersion::DMN_TYPE);
  }

  /// Writes the fields after the version, up to the type where `typed` is
  /// false.
  fn encode_fields(&self, buf: &mut impl EncodeBuf, typed: bool) {
    self.pro_reg_tx_hash.encode(buf);
    self.confirmed_hash.encode(buf);
    match &self.net_info {
      NetInfo::Legacy(v1) => v1.encode(buf),
      NetInfo::Extended(v2) => v2.encode(buf),
    }
    self.operator_key.encode(buf);
    self.voting_key_id.encode(buf);
    self.is_valid.encode(buf);
    if typed && self.version >= 2 {
      self.mn_type.to_base().encode(buf);
      if self.mn_type == MnType::Evo {
        if self.version < PROTX_VERSION_EXT_ADDR {
          self.platform_http_port.unwrap_or(0).encode(buf);
        }
        self.platform_node_id.unwrap_or_default().encode(buf);
      }
    }
  }

  /// Builds an entry whose net info form and operator key scheme follow
  /// `version`.
  ///
  /// # Errors
  ///
  /// Returns [`NetInfoVersionMismatch`] for extended net info below version 3
  /// or legacy net info from it.
  #[expect(clippy::too_many_arguments, reason = "one argument per wire field")]
  pub fn new(
    version: u16,
    pro_reg_tx_hash: TxHash,
    confirmed_hash: BlockHash,
    net_info: NetInfo,
    operator_key: [u8; BLS_PK_LEN],
    voting_key_id: PubKeyHash,
    is_valid: bool,
    mn_type: MnType,
    platform_http_port: Option<u16>,
    platform_node_id: Option<PlatformNodeId>,
  ) -> Result<Self, NetInfoVersionMismatch> {
    if matches!(net_info, NetInfo::Extended(_)) != (version >= PROTX_VERSION_EXT_ADDR) {
      return Err(NetInfoVersionMismatch);
    }
    Ok(Self {
      version,
      pro_reg_tx_hash,
      confirmed_hash,
      net_info,
      operator_key: BlsPubKey::from_bytes(operator_key, BlsScheme::from_protx_version(version)),
      voting_key_id,
      is_valid,
      mn_type,
      platform_http_port,
      platform_node_id,
    })
  }

  /// Entry version.
  pub const fn version(&self) -> u16 {
    self.version
  }

  /// Network addresses, legacy below version 3 and extended from it.
  pub const fn net_info(&self) -> &NetInfo {
    &self.net_info
  }

  /// BLS operator public key, in the scheme of the entry version.
  pub const fn operator_key(&self) -> &BlsPubKey {
    &self.operator_key
  }
}

/// Computes the merkle root of a full simplified masternode list along with
/// a mutation flag. Entries are ordered by ProRegTx hash first, so the order
/// of `entries` does not change the root.
///
/// The flag is `true` when a row pairs two equal hashes, which a list with a
/// duplicate entry can produce.
pub fn sml_merkle_root(entries: &[SimplifiedMnListEntry]) -> (MerkleRoot, bool) {
  let mut sorted: Vec<&SimplifiedMnListEntry> = entries.iter().collect();
  sorted.sort_by_key(|entry| entry.pro_reg_tx_hash);
  let leaves: Vec<Hash256> = sorted.iter().map(|entry| entry.hash()).collect();
  let (root, mutated) = merkle_root_mutated(&leaves);
  (MerkleRoot::from_lendian(*root.as_bytes()), mutated)
}

/// Field set that builds the entry through [`SimplifiedMnListEntry::new`].
#[cfg(feature = "serde")]
#[derive(::serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct __SmlEntryFields {
  version: u16,
  pro_reg_tx_hash: TxHash,
  confirmed_hash: BlockHash,
  net_info: NetInfo,
  #[serde(deserialize_with = "dash_primitives::serialize::bls::pk_bytes")]
  operator_key: [u8; BLS_PK_LEN],
  voting_key_id: PubKeyHash,
  is_valid: bool,
  mn_type: MnType,
  #[serde(rename = "platformHTTPPort")]
  platform_http_port: Option<u16>,
  platform_node_id: Option<PlatformNodeId>,
}

#[cfg(feature = "serde")]
impl TryFrom<__SmlEntryFields> for SimplifiedMnListEntry {
  type Error = NetInfoVersionMismatch;

  fn try_from(fields: __SmlEntryFields) -> Result<Self, Self::Error> {
    Self::new(
      fields.version,
      fields.pro_reg_tx_hash,
      fields.confirmed_hash,
      fields.net_info,
      fields.operator_key,
      fields.voting_key_id,
      fields.is_valid,
      fields.mn_type,
      fields.platform_http_port,
      fields.platform_node_id,
    )
  }
}

impl fmt::Display for SimplifiedMnListEntry {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "{}", self.pro_reg_tx_hash)
  }
}

#[cfg(all(test, feature = "serde"))]
mod tests {
  use super::*;
  use crate::{CommandString, P2pMsg};

  use dash_dev::{assert_serde_rt, check_wire, json_rejects, Corpus};
  use dash_pkc::bls::{BlsScChia, BlsSecretKey};
  use dash_primitives::{AddrV1, AddrV2, NIEntry, NIPurpose, ServiceV1, ServiceV2};
  use hex_conservative::decode_to_vec;
  use rstest::rstest;

  fn corpus_diff() -> MnListDiffPayload {
    let corpus = Corpus::open(env!("CARGO_MANIFEST_DIR"), "mnlistdiff");
    let items: Vec<_> = corpus
      .entries::<MnListDiffPayload>("mnlistdiff", |_, _, _| {})
      .into_values()
      .collect();
    items[0].clone()
  }

  /// Corpus diff reduced to what every layout carries. Entries are version 1
  /// regular masternodes, and the chainlock signatures are left out unless
  /// `cl_sigs` is set.
  fn diff_for(cl_sigs: bool) -> MnListDiffPayload {
    let mut diff = corpus_diff();
    for entry in &mut diff.mn_list {
      entry.version = 1;
      entry.operator_key = BlsPubKey::from_bytes(*entry.operator_key.as_bytes(), BlsScheme::Legacy);
      entry.mn_type = MnType::Regular;
      entry.platform_http_port = None;
      entry.platform_node_id = None;
    }
    if !cl_sigs {
      diff.quorum_cl_sigs.clear();
    }
    diff
  }

  fn enc(value: &impl BaseCodec) -> Vec<u8> {
    let mut buf = Vec::new();
    value.encode(&mut buf);
    buf
  }

  /// Builds the wire image from the field encodings and the gates a protocol
  /// version opens.
  fn layout(
    diff: &MnListDiffPayload,
    version_first: bool,
    version_mid: bool,
    entry_version: bool,
    cl_sigs: bool,
  ) -> Vec<u8> {
    let version = enc(&diff.version);
    let mut out = Vec::new();
    if version_first {
      out.extend(&version);
    }
    for part in [
      enc(&diff.base_block_hash),
      enc(&diff.block_hash),
      enc(&diff.cb_tx_merkle_tree),
      enc(&diff.cb_tx),
    ] {
      out.extend(part);
    }
    if version_mid {
      out.extend(&version);
    }
    out.extend(enc(&diff.deleted_mns));
    out.extend(enc(&CompactSize::from(diff.mn_list.len())));
    for entry in &diff.mn_list {
      if entry_version {
        out.extend(enc(&entry.version));
      }
      out.extend(enc(&entry.pro_reg_tx_hash));
      out.extend(enc(&entry.confirmed_hash));
      match &entry.net_info {
        NetInfo::Legacy(v1) => out.extend(enc(v1)),
        NetInfo::Extended(v2) => out.extend(enc(v2)),
      }
      entry.operator_key.encode(&mut out);
      out.extend(enc(&entry.voting_key_id));
      out.extend(enc(&entry.is_valid));
    }
    out.extend(enc(&diff.deleted_quorums));
    out.extend(enc(&diff.new_quorums));
    if cl_sigs {
      out.extend(enc(&diff.quorum_cl_sigs));
    }
    out
  }

  #[rstest]
  #[case::min_peer(70221, false, false, false, false)]
  #[case::bls_scheme(70225, false, true, false, false)]
  #[case::dmn_type(70227, false, true, false, false)]
  #[case::smnle_versioned(70228, false, true, true, false)]
  #[case::version_order(70229, true, false, true, false)]
  #[case::chainlocks(70230, true, false, true, true)]
  #[case::current(70242, true, false, true, true)]
  fn layout_follows_the_protocol_version(
    #[case] version: u32,
    #[case] version_first: bool,
    #[case] version_mid: bool,
    #[case] entry_version: bool,
    #[case] cl_sigs: bool,
  ) {
    let version = ProtocolVersion(version);
    let diff = diff_for(cl_sigs);
    let raw = layout(&diff, version_first, version_mid, entry_version, cl_sigs);

    let mut buf = Vec::new();
    diff.encode_versioned(&mut buf, version);
    assert_eq!(buf, raw);

    let mut cursor = raw.as_slice();
    assert_eq!(
      MnListDiffPayload::decode_versioned(&mut cursor, version),
      Ok(diff.clone())
    );
    assert!(cursor.is_empty());

    assert_eq!(
      P2pMsg::decode_payload_with_version(&CommandString::MNLISTDIFF, &raw, version),
      Ok(P2pMsg::MnListDiff(MnListDiff { payload: diff }))
    );
  }

  /// A diff version left off the wire decodes as 1.
  #[rstest]
  fn absent_diff_version_decodes_as_one() {
    let mut diff = diff_for(false);
    diff.version = 7;
    let raw = layout(&diff, false, false, false, false);
    let back = MnListDiffPayload::decode_versioned(&mut raw.as_slice(), ProtocolVersion::MIN_PEER);
    assert_eq!(back.map(|back| back.version), Ok(1));
  }

  /// An entry version 2 carries its type only from `DMN_TYPE`, and an entry
  /// version left off the wire decodes as 1, which carries no type.
  #[rstest]
  #[case::below_dmn_type(70226, false)]
  #[case::at_dmn_type(70227, true)]
  fn entry_type_needs_dmn_type(#[case] version: u32, #[case] typed: bool) {
    let mut entry = corpus_diff().mn_list[0].clone();
    entry.version = 2;
    entry.mn_type = MnType::Regular;
    let mut buf = Vec::new();
    entry.encode_versioned(&mut buf, ProtocolVersion(version));
    let mut untyped = Vec::new();
    entry.encode_versioned(&mut untyped, ProtocolVersion(70226));
    assert_eq!(buf.len(), untyped.len() + if typed { 2 } else { 0 });

    let back = SimplifiedMnListEntry::decode_versioned(&mut untyped.as_slice(), ProtocolVersion(70226));
    assert_eq!(back.map(|back| (back.version, back.mn_type)), Ok((1, MnType::Regular)));
  }

  #[rstest]
  fn corpus_mnlistdiff() {
    let corpus = Corpus::open(env!("CARGO_MANIFEST_DIR"), "mnlistdiff");
    let items = corpus.entries::<MnListDiffPayload>("mnlistdiff", check_wire);
    assert_serde_rt("mnlistdiff", &items);
  }

  /// The coinbase merkle tree proves the coinbase transaction at position 0.
  #[rstest]
  fn cb_tx_merkle_tree_matches_the_coinbase() {
    let diff = corpus_diff();
    let cb_tx = Hash256::from_lendian(*diff.cb_tx.hash().as_bytes());
    let matched = diff.cb_tx_merkle_tree.extract_matches().map(|matches| matches.matched);
    assert_eq!(matched, Ok(vec![(0, cb_tx)]));
  }

  #[rstest]
  #[case::legacy_bls(70240, 1, BlsScheme::Legacy)]
  #[case::basic_bls(70240, 2, BlsScheme::Basic)]
  #[case::unversioned(70227, 2, BlsScheme::Legacy)]
  fn operator_key_is_tagged_from_the_entry_version(
    #[case] version: u32,
    #[case] entry_version: u16,
    #[case] scheme: BlsScheme,
  ) {
    let mut entry = corpus_diff().mn_list[0].clone();
    entry.version = entry_version;
    entry.mn_type = MnType::Regular;
    let mut buf = Vec::new();
    entry.encode_versioned(&mut buf, ProtocolVersion(version));
    let back = SimplifiedMnListEntry::decode_versioned(&mut buf.as_slice(), ProtocolVersion(version));
    assert_eq!(
      back.map(|back| back.operator_key),
      Ok(BlsPubKey::from_bytes(*entry.operator_key.as_bytes(), scheme))
    );
  }

  #[rstest]
  #[case::legacy_bls(1, BlsScheme::Legacy)]
  #[case::basic_bls(2, BlsScheme::Basic)]
  fn json_operator_key_is_tagged_from_the_entry_version(#[case] entry_version: u16, #[case] scheme: BlsScheme) {
    let mut entry = corpus_diff().mn_list[0].clone();
    entry.version = entry_version;
    let back: SimplifiedMnListEntry = dash_dev::from_json(&dash_dev::to_json(&entry));
    assert_eq!(back.operator_key.scheme(), scheme);
  }

  fn extended() -> NetInfo {
    let service = ServiceV2 {
      addr: AddrV2::Ipv4([1, 2, 3, 4]),
      port: 9999,
    };
    NetInfo::Extended(NetInfoV2::new(vec![(
      NIPurpose::CoreP2p,
      vec![NIEntry::Service(service)],
    )]))
  }

  /// Corpus entry rebuilt as an evo masternode at `version`, with net info
  /// of the form `version` takes.
  fn evo_entry(version: u16) -> SimplifiedMnListEntry {
    let entry = corpus_diff().mn_list[0].clone();
    let net_info = if version >= PROTX_VERSION_EXT_ADDR {
      extended()
    } else {
      entry.net_info.clone()
    };
    SimplifiedMnListEntry {
      version,
      net_info,
      operator_key: BlsPubKey::from_bytes(*entry.operator_key.as_bytes(), BlsScheme::from_protx_version(version)),
      mn_type: MnType::Evo,
      platform_http_port: (version < PROTX_VERSION_EXT_ADDR).then_some(443),
      platform_node_id: Some(PlatformNodeId::from([7; 20])),
      ..entry
    }
  }

  /// Version 3 entries carry extended net info and no platform HTTP port.
  #[rstest]
  #[case::basic_bls(2)]
  #[case::ext_addr(3)]
  fn ext_addr_entry_layout(#[case] version: u16) {
    let entry = evo_entry(version);
    let mut raw = enc(&version);
    raw.extend(enc(&entry.pro_reg_tx_hash));
    raw.extend(enc(&entry.confirmed_hash));
    match &entry.net_info {
      NetInfo::Legacy(v1) => raw.extend(enc(v1)),
      NetInfo::Extended(v2) => raw.extend(enc(v2)),
    }
    entry.operator_key.encode(&mut raw);
    raw.extend(enc(&entry.voting_key_id));
    raw.extend(enc(&entry.is_valid));
    raw.extend(enc(&MnType::Evo.to_base()));
    if let Some(port) = entry.platform_http_port {
      raw.extend(enc(&port));
    }
    raw.extend(enc(&entry.platform_node_id.unwrap_or_default()));

    assert_eq!(enc(&entry), raw);
    assert_eq!(SimplifiedMnListEntry::decode(&mut raw.as_slice()), Ok(entry));
  }

  /// Version 3 entries as written at the current protocol, with zero bytes
  /// for the fields that every version shares.
  #[rstest]
  #[case::empty_regular(
    "0100", // version 1, no purposes
    NetInfoV2::new(vec![]),
    MnType::Regular,
    "0000", // regular
  )]
  #[case::ipv4_regular(
    concat!(
      "01",               // version 1
      "01",               // one purpose
      "00", "01",         // core P2P, one entry
      "01", "01", "04",   // service, IPv4, 4 bytes
      "01020304", "270f", // 1.2.3.4, port 9999
    ),
    NetInfoV2::new(vec![(
      NIPurpose::CoreP2p,
      vec![NIEntry::Service(ServiceV2 { addr: AddrV2::Ipv4([1, 2, 3, 4]), port: 9999 })],
    )]),
    MnType::Regular,
    "0000", // regular
  )]
  #[case::domain_evo(
    concat!(
      "01",                     // version 1
      "01",                     // one purpose
      "02", "01",               // platform HTTPS, one entry
      "02", "0b",               // domain, 11 bytes
      "6578616d706c652e636f6d", // "example.com"
      "01bb",                   // port 443
    ),
    NetInfoV2::new(vec![(
      NIPurpose::PlatformHttps,
      vec![NIEntry::Domain { name: b"example.com".to_vec(), port: 443 }],
    )]),
    MnType::Evo,
    concat!("0100", "0000000000000000000000000000000000000000"), // evo, node id
  )]
  fn ext_addr_entry_vectors(
    #[case] net_info_hex: &str,
    #[case] net_info: NetInfoV2,
    #[case] mn_type: MnType,
    #[case] type_hex: &str,
  ) {
    let hex = [
      "0300",
      &"00".repeat(64),
      net_info_hex,
      &"00".repeat(BLS_PK_LEN + 20),
      "01",
      type_hex,
    ]
    .concat();
    let raw = decode_to_vec(&hex).unwrap_or_default();
    let entry = SimplifiedMnListEntry::decode(&mut raw.as_slice());
    assert_eq!(
      entry
        .as_ref()
        .map(|entry| (entry.net_info(), entry.mn_type, entry.platform_http_port)),
      Ok((&NetInfo::Extended(net_info), mn_type, None))
    );
    assert_eq!(entry.map(|entry| enc(&entry)), Ok(raw));
  }

  #[rstest]
  #[case::legacy_below_ext_addr(2, false, true)]
  #[case::extended_below_ext_addr(2, true, false)]
  #[case::legacy_at_ext_addr(3, false, false)]
  #[case::extended_at_ext_addr(3, true, true)]
  #[case::extended_above_ext_addr(4, true, true)]
  fn new_matches_net_info_to_the_version(#[case] version: u16, #[case] is_extended: bool, #[case] ok: bool) {
    let entry = corpus_diff().mn_list[0].clone();
    let net_info = if is_extended {
      extended()
    } else {
      entry.net_info.clone()
    };
    let built = SimplifiedMnListEntry::new(
      version,
      entry.pro_reg_tx_hash,
      entry.confirmed_hash,
      net_info,
      *entry.operator_key.as_bytes(),
      entry.voting_key_id,
      entry.is_valid,
      MnType::Regular,
      None,
      None,
    );
    assert_eq!(built.err(), (!ok).then_some(NetInfoVersionMismatch));
  }

  #[rstest]
  fn json_ext_addr_entry_round_trips() {
    let entry = evo_entry(3);
    let back: SimplifiedMnListEntry = dash_dev::from_json(&dash_dev::to_json(&entry));
    assert_eq!(back, entry);
  }

  #[rstest]
  fn json_rejects_net_info_of_the_wrong_form() {
    let mut entry = evo_entry(2);
    entry.version = 3;
    assert!(json_rejects::<SimplifiedMnListEntry>(&dash_dev::to_json(&entry)));
  }

  /// Entry `i` of the reference `simplifiedmns_merkleroots` test, a version 1
  /// entry whose fields all derive from `i`.
  fn merkleroots_entry(i: u8) -> SimplifiedMnListEntry {
    let mut bytes = [0u8; 32];
    bytes[0] = i;
    let secret = BlsSecretKey::<BlsScChia>::from_bytes(&bytes);
    assert!(secret.is_ok(), "entry {i}: bad secret key");
    let operator_key = secret.map_or([0; BLS_PK_LEN], |secret| secret.public_key().to_bytes());
    let mut voting_key_id = [0u8; 20];
    voting_key_id[0] = i;
    let service = ServiceV1 {
      addr: AddrV1::from([0, 0, 0, i]),
      port: u16::from(i),
    };
    SimplifiedMnListEntry {
      version: 1,
      pro_reg_tx_hash: TxHash::from_lendian(bytes),
      confirmed_hash: BlockHash::from_lendian(bytes),
      net_info: NetInfo::Legacy(NetInfoV1(service)),
      operator_key: BlsPubKey::from_bytes(operator_key, BlsScheme::Legacy),
      voting_key_id: PubKeyHash::from(voting_key_id),
      is_valid: true,
      mn_type: MnType::Regular,
      platform_http_port: None,
      platform_node_id: None,
    }
  }

  // Leaf hashes of entries 1 to 15 in the reference
  // `simplifiedmns_merkleroots` test.
  const MERKLEROOTS_LEAVES: [&str; 15] = [
    "3a1010e28226558560e5296bcee6bf0b9b963b73a1514f5aa2885e270f6b90c1",
    "85d3d93b28689128daf3a41d706ae5002f447b9b6372776f0ca9d53b31146884",
    "8930eee6bd2e7971a7090edfb79f74c00a12280e59adfc2cc99d406a01e368f9",
    "dc2e69caa0ef97e8f5cf40a9530641bd4933dd8c9ad533054537728f7e5f58c2",
    "3e4a0e0a0d2ed397fa27221de3047de21f50d17d0ba43738cbdb9fee96c7cb46",
    "eb18476a1496e1cb912b1d4dd93314b78c6a679d83cae8e144a717b967dc4b8c",
    "6c0d01fa40ac11d7b523facd2bf5632c83f7e4df3f60fd1b364ea90f6c852156",
    "c9e3e69d54e6e95b280ae102593fe114cf4620fa89dd88da1a146ada08815d68",
    "1023f67f735e8e9403d5f083e7a17489619b1790feac4f6b133e9dda15999ae6",
    "5d5fc77944f7c72df236a5baf460c7b9a947144d54d0953521f1494c8a2f7aaa",
    "ac7db66820de3c7506f8c6415fd352e36ac5f27c6adbdfb74de3e109d0d277df",
    "cbc25ca965d0fa69a1fdc1d796b8ee2726a0e2137414e92fb9541630e3189901",
    "ac9934c4049ae952d41fb38e7e9659a558a5ce748bdb7fb613741598d1b16a27",
    "a61177eb14450bb8c56e5f0547035e0f3a70fe46f36901351cc568b2e48e29d0",
    "67798d40a2196f446114c68d86445fe088750515a96eb65392c6bcfac8f3be9b",
  ];

  #[rstest]
  fn hash_matches_the_reference_leaves() {
    for (i, leaf) in (1..=15).zip(MERKLEROOTS_LEAVES) {
      assert_eq!(format!("{}", merkleroots_entry(i).hash()), leaf, "entry {i}");
    }
  }

  /// The hash covers the wire encoding without its leading version.
  #[rstest]
  #[case::basic_bls(2)]
  #[case::ext_addr(3)]
  fn hash_leaves_out_the_version(#[case] version: u16) {
    let entry = evo_entry(version);
    let raw = enc(&entry);
    let expected = Hash256::from_lendian(sha256d::Hash::hash(&raw[2..]).to_byte_array());
    assert_eq!(entry.hash(), expected);
  }

  // Merkle root of entries 1 to 15 in the reference
  // `simplifiedmns_merkleroots` test.
  const MERKLEROOTS_ROOT: &str = "0bae2176078cf42fa3e1fda761d4255d1c1c54777c6a793d0ab2b07c85ed4022";

  #[rstest]
  #[case::ascending(false)]
  #[case::descending(true)]
  fn sml_merkle_root_matches_the_reference(#[case] reversed: bool) {
    let mut entries: Vec<_> = (1..=15).map(merkleroots_entry).collect();
    if reversed {
      entries.reverse();
    }
    let (root, mutated) = sml_merkle_root(&entries);
    assert_eq!((format!("{root}").as_str(), mutated), (MERKLEROOTS_ROOT, false));
  }

  /// A duplicated last entry keeps the root and sets the mutation flag.
  #[rstest]
  fn sml_merkle_root_flags_a_duplicate_entry() {
    let mut entries: Vec<_> = (1..=15).map(merkleroots_entry).collect();
    entries.push(merkleroots_entry(15));
    let (root, mutated) = sml_merkle_root(&entries);
    assert_eq!((format!("{root}").as_str(), mutated), (MERKLEROOTS_ROOT, true));
  }

  #[rstest]
  fn corpus_mnlistdiff_passes_its_checks() {
    assert_eq!(corpus_diff().check(), None);
  }

  #[rstest]
  #[case::evo_basic_bls(evo_entry(2), None)]
  #[case::evo_ext_addr(evo_entry(3), None)]
  #[case::version_zero(
    SimplifiedMnListEntry { version: 0, ..merkleroots_entry(1) },
    Some(SmlEntryInvalid::BadVersion { version: 0 }),
  )]
  #[case::version_above_ext_addr(
    SimplifiedMnListEntry { version: 4, ..evo_entry(3) },
    Some(SmlEntryInvalid::BadVersion { version: 4 }),
  )]
  #[case::evo_legacy_bls(
    SimplifiedMnListEntry { mn_type: MnType::Evo, ..merkleroots_entry(1) },
    Some(SmlEntryInvalid::TypeBeforeBasicBls { mn_type: MnType::Evo }),
  )]
  #[case::http_port_at_ext_addr(
    SimplifiedMnListEntry { platform_http_port: Some(443), ..evo_entry(3) },
    Some(SmlEntryInvalid::BadPlatformFields),
  )]
  #[case::no_http_port_below_ext_addr(
    SimplifiedMnListEntry { platform_http_port: None, ..evo_entry(2) },
    Some(SmlEntryInvalid::BadPlatformFields),
  )]
  #[case::no_node_id(
    SimplifiedMnListEntry { platform_node_id: None, ..evo_entry(3) },
    Some(SmlEntryInvalid::BadPlatformFields),
  )]
  #[case::regular_with_node_id(
    SimplifiedMnListEntry { mn_type: MnType::Regular, platform_http_port: None, ..evo_entry(3) },
    Some(SmlEntryInvalid::BadPlatformFields),
  )]
  fn entry_check(#[case] entry: SimplifiedMnListEntry, #[case] expected: Option<SmlEntryInvalid>) {
    assert_eq!(entry.check(), expected);
  }

  #[rstest]
  fn diff_check_reports_the_failing_entry() {
    let mut diff = corpus_diff();
    diff.mn_list[1].version = 0;
    assert_eq!(
      diff.check(),
      Some(MnListDiffInvalid::Entry {
        index: 1,
        error: SmlEntryInvalid::BadVersion { version: 0 },
      })
    );
  }

  /// Corpus diff whose first chainlock signature covers `indices`.
  fn diff_with_cl_indices(indices: &[u16]) -> MnListDiffPayload {
    let mut diff = corpus_diff();
    diff.quorum_cl_sigs[0].index_set = indices.to_vec();
    diff
  }

  #[rstest]
  fn diff_check_rejects_a_repeated_cl_sig() {
    let mut diff = corpus_diff();
    let first = diff.quorum_cl_sigs[0].clone();
    diff.quorum_cl_sigs.push(first);
    assert_eq!(diff.check(), Some(MnListDiffInvalid::DuplicateClSig));
  }

  #[rstest]
  #[case::repeated(&[0, 0], Some(MnListDiffInvalid::UnsortedClSigIndices))]
  #[case::descending(&[1, 0], Some(MnListDiffInvalid::UnsortedClSigIndices))]
  #[case::ascending(&[0, 1], None)]
  fn diff_check_wants_ascending_cl_indices(#[case] indices: &[u16], #[case] expected: Option<MnListDiffInvalid>) {
    assert_eq!(diff_with_cl_indices(indices).check(), expected);
  }

  #[rstest]
  fn diff_check_rejects_a_cl_index_past_the_new_quorums() {
    let index = u16::try_from(corpus_diff().new_quorums.len()).unwrap_or(u16::MAX);
    assert_eq!(
      diff_with_cl_indices(&[index]).check(),
      Some(MnListDiffInvalid::ClSigIndexOutOfRange { index })
    );
  }
}
