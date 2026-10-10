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

#[cfg(feature = "serde")]
use dash_pkc::bls::BLS_PK_LEN;
use dash_pkc::bls::{BlsScIetf, BlsSigBytes};
use dash_primitives::{
  hash_impl, BlockHash, BlsPubKey, BlsScheme, Commitment, LlmqType, MnType, PlatformNodeId, ServiceV1, Transaction,
  TxHash,
};
use dash_script::PubKeyHash;
use dash_types::codec::{BaseCodec, DecodeError, EncodeBuf};
use dash_types::{type_id::TypeId, CompactSize, Numeric};

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
  /// Number of transactions in the coinbase merkle proof.
  pub total_transactions: u32,
  /// Merkle branch hashes.
  pub merkle_hashes: Vec<TxHash>,
  /// Merkle branch flag bytes.
  #[cfg_attr(feature = "serde", serde(with = "dash_types::serialize::hex"))]
  pub merkle_flags: Vec<u8>,
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
    let total_transactions = u32::decode(data)?;
    let merkle_hashes = Vec::decode(data)?;
    let merkle_flags = Vec::decode(data)?;
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
      total_transactions,
      merkle_hashes,
      merkle_flags,
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
    self.total_transactions.encode(buf);
    self.merkle_hashes.encode(buf);
    self.merkle_flags.encode(buf);
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

/// A single entry in the simplified masternode list.
#[derive(Clone, Debug, Eq, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase", from = "__SmlEntryFields"))]
pub struct SimplifiedMnListEntry {
  /// Entry serialisation version.
  pub version: u16,
  /// Masternode registration transaction hash.
  pub pro_reg_tx_hash: TxHash,
  /// Block hash at confirmation depth.
  pub confirmed_hash: BlockHash,
  /// Network service address.
  pub service: ServiceV1,
  /// BLS operator public key, in the scheme of the entry version.
  pub operator_key: BlsPubKey,
  /// Voting key hash (HASH160).
  pub voting_key_id: PubKeyHash,
  /// Whether this masternode is currently valid.
  pub is_valid: bool,
  /// Masternode type (Regular or Evo).
  pub mn_type: MnType,
  /// Platform HTTP port (Evo masternodes only).
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

hash_impl!(SimplifiedMnListEntry);

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
    let service = ServiceV1::decode(data)?;
    let operator_key = BlsPubKey::decode(data, BlsScheme::from_protx_version(entry_version))?;
    let voting_key_id = PubKeyHash::decode(data)?;
    let is_valid = bool::decode(data)?;

    let mn_type = if version >= ProtocolVersion::DMN_TYPE && entry_version >= 2 {
      MnType::from_base(u16::decode(data)?)
    } else {
      MnType::Regular
    };

    let (platform_http_port, platform_node_id) = if mn_type == MnType::Evo {
      (Some(u16::decode(data)?), Some(PlatformNodeId::decode(data)?))
    } else {
      (None, None)
    };

    Ok(Self {
      version: entry_version,
      pro_reg_tx_hash,
      confirmed_hash,
      service,
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
    self.pro_reg_tx_hash.encode(buf);
    self.confirmed_hash.encode(buf);
    self.service.encode(buf);
    self.operator_key.encode(buf);
    self.voting_key_id.encode(buf);
    self.is_valid.encode(buf);
    if version >= ProtocolVersion::DMN_TYPE && self.version >= 2 {
      self.mn_type.to_base().encode(buf);
      if self.mn_type == MnType::Evo {
        self.platform_http_port.unwrap_or(0).encode(buf);
        self.platform_node_id.unwrap_or_default().encode(buf);
      }
    }
  }
}

/// Field set that tags the operator key from the entry version.
#[cfg(feature = "serde")]
#[derive(::serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct __SmlEntryFields {
  version: u16,
  pro_reg_tx_hash: TxHash,
  confirmed_hash: BlockHash,
  service: ServiceV1,
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
impl From<__SmlEntryFields> for SimplifiedMnListEntry {
  fn from(fields: __SmlEntryFields) -> Self {
    Self {
      version: fields.version,
      pro_reg_tx_hash: fields.pro_reg_tx_hash,
      confirmed_hash: fields.confirmed_hash,
      service: fields.service,
      operator_key: BlsPubKey::from_bytes(fields.operator_key, BlsScheme::from_protx_version(fields.version)),
      voting_key_id: fields.voting_key_id,
      is_valid: fields.is_valid,
      mn_type: fields.mn_type,
      platform_http_port: fields.platform_http_port,
      platform_node_id: fields.platform_node_id,
    }
  }
}

impl fmt::Display for SimplifiedMnListEntry {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "{}", self.pro_reg_tx_hash)
  }
}

#[cfg(all(test, feature = "serde"))]
#[expect(clippy::unwrap_used, reason = "test code")]
mod tests {
  use super::*;
  use crate::{CommandString, P2pMsg};

  use dash_dev::{assert_serde_rt, check_wire, Corpus};
  use rstest::rstest;

  fn corpus_diff() -> MnListDiffPayload {
    let corpus = Corpus::open(env!("CARGO_MANIFEST_DIR"), "mnlistdiff");
    let items = corpus.entries::<MnListDiffPayload>("mnlistdiff", |_, _, _| {});
    items.into_values().next().unwrap()
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
      enc(&diff.total_transactions),
      enc(&diff.merkle_hashes),
      enc(&diff.merkle_flags),
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
      out.extend(enc(&entry.service));
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
  #[case::current(70240, true, false, true, true)]
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
    assert_eq!(MnListDiffPayload::decode_versioned(&mut cursor, version).unwrap(), diff);
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
    let back = MnListDiffPayload::decode_versioned(&mut raw.as_slice(), ProtocolVersion::MIN_PEER).unwrap();
    assert_eq!(back.version, 1);
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

    let back = SimplifiedMnListEntry::decode_versioned(&mut untyped.as_slice(), ProtocolVersion(70226)).unwrap();
    assert_eq!((back.version, back.mn_type), (1, MnType::Regular));
  }

  #[rstest]
  fn corpus_mnlistdiff() {
    let corpus = Corpus::open(env!("CARGO_MANIFEST_DIR"), "mnlistdiff");
    let items = corpus.entries::<MnListDiffPayload>("mnlistdiff", check_wire);
    assert_serde_rt("mnlistdiff", &items);
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
    let back = SimplifiedMnListEntry::decode_versioned(&mut buf.as_slice(), ProtocolVersion(version)).unwrap();
    assert_eq!(back.operator_key.scheme(), scheme);
    assert_eq!(back.operator_key.as_bytes(), entry.operator_key.as_bytes());
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
}
