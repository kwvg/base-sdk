//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Simplified masternode list types for `getmnlistd`/`mnlistdiff`.

use crate::prelude::*;

use dash_primitives::payload::Commitment;
use dash_primitives::{BlockHash, CService, LlmqType, MnType, Transaction, TxHash};
use dash_script::KeyId;
use dash_types::codec::{self, Codec, DecodeError, NumCodec};
use dash_types::{BlsPublicKeyBytes, BlsSignatureBytes, PlatformNodeId};

use core::fmt;

/// Maximum number of entries in a single MN list diff.
const MAX_MN_LIST: usize = 10_000;
/// Maximum number of deleted MN hashes.
const MAX_DELETED_MNS: usize = 10_000;
/// Maximum number of quorum entries.
const MAX_QUORUMS: usize = 1_000;
/// Maximum number of merkle hashes.
const MAX_MERKLE: usize = 100_000;
/// Maximum merkle flag bytes.
const MAX_MERKLE_FLAGS: usize = 100_000;

/// A single entry in the simplified masternode list.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct SimplifiedMnListEntry {
  /// Entry serialisation version.
  pub version: u16,
  /// Masternode registration transaction hash.
  pub pro_reg_tx_hash: TxHash,
  /// Block hash at confirmation depth.
  pub confirmed_hash: BlockHash,
  /// Network service address.
  pub service: CService,
  /// BLS operator public key.
  pub operator_key: BlsPublicKeyBytes,
  /// Voting key hash (HASH160).
  pub voting_key_id: KeyId,
  /// Whether this masternode is currently valid.
  pub is_valid: bool,
  /// Masternode type (Regular or Evo).
  pub mn_type: MnType,
  /// Platform HTTP port (Evo masternodes only).
  pub platform_http_port: Option<u16>,
  /// Platform node ID (Evo masternodes only).
  pub platform_node_id: Option<PlatformNodeId>,
}

impl Codec for SimplifiedMnListEntry {
  fn decode(data: &mut &[u8]) -> Result<Self, DecodeError> {
    let version = u16::decode(data)?;
    let pro_reg_tx_hash = TxHash::decode(data)?;
    let confirmed_hash = BlockHash::decode(data)?;
    let service = CService::decode(data)?;
    let operator_key = BlsPublicKeyBytes::decode(data)?;
    let voting_key_id = KeyId::decode(data)?;
    let is_valid = bool::decode(data)?;

    // nType is gated by the entry's version
    let mn_type = if version >= 2 {
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
      version,
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

  fn encode(&self, buf: &mut Vec<u8>) {
    self.version.encode(buf);
    self.pro_reg_tx_hash.encode(buf);
    self.confirmed_hash.encode(buf);
    self.service.encode(buf);
    self.operator_key.encode(buf);
    self.voting_key_id.encode(buf);
    self.is_valid.encode(buf);
    // nType and platform fields are gated by the entry's version
    if self.version >= 2 {
      self.mn_type.to_base().encode(buf);
      if self.mn_type == MnType::Evo {
        self.platform_http_port.unwrap_or(0).encode(buf);
        self.platform_node_id.unwrap_or_default().encode(buf);
      }
    }
  }
}

crate::codec::impl_p2p!(SimplifiedMnListEntry);

impl fmt::Display for SimplifiedMnListEntry {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "{}", self.pro_reg_tx_hash)
  }
}

/// Deleted quorum identifier (type + hash).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct DeletedQuorum {
  /// LLMQ type.
  pub llmq_type: LlmqType,
  /// Quorum hash.
  pub hash: BlockHash,
}

impl Codec for DeletedQuorum {
  fn decode(data: &mut &[u8]) -> Result<Self, DecodeError> {
    Ok(Self {
      llmq_type: LlmqType::from_base(u8::decode(data)?),
      hash: BlockHash::decode(data)?,
    })
  }

  fn encode(&self, buf: &mut Vec<u8>) {
    self.llmq_type.to_base().encode(buf);
    self.hash.encode(buf);
  }
}

crate::codec::impl_p2p!(DeletedQuorum);

/// Chainlock signature entry in the MN list diff.
///
/// Each entry maps a BLS signature to the indices (within
/// `new_quorums`) of the quorums it covers.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct QuorumClSig {
  /// BLS signature.
  pub sig: BlsSignatureBytes,
  /// Indices into the `new_quorums` vector.
  pub index_set: Vec<u16>,
}

impl Codec for QuorumClSig {
  fn decode(data: &mut &[u8]) -> Result<Self, DecodeError> {
    Ok(Self {
      sig: BlsSignatureBytes::decode(data)?,
      index_set: codec::read_vec(data, MAX_QUORUMS)?,
    })
  }

  fn encode(&self, buf: &mut Vec<u8>) {
    self.sig.encode(buf);
    codec::write_vec(&self.index_set, buf);
  }
}

crate::codec::impl_p2p!(QuorumClSig);

/// Full masternode list diff payload.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
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

impl Codec for MnListDiffPayload {
  fn decode(data: &mut &[u8]) -> Result<Self, DecodeError> {
    Ok(Self {
      version: u16::decode(data)?,
      base_block_hash: BlockHash::decode(data)?,
      block_hash: BlockHash::decode(data)?,
      total_transactions: u32::decode(data)?,
      merkle_hashes: codec::read_vec(data, MAX_MERKLE)?,
      merkle_flags: codec::read_blob(data, MAX_MERKLE_FLAGS)?,
      cb_tx: Transaction::decode(data)?,
      deleted_mns: codec::read_vec(data, MAX_DELETED_MNS)?,
      mn_list: codec::read_vec(data, MAX_MN_LIST)?,
      deleted_quorums: codec::read_vec(data, MAX_QUORUMS)?,
      new_quorums: codec::read_vec(data, MAX_QUORUMS)?,
      // Chainlock signatures (protocol >= 70230).
      quorum_cl_sigs: codec::read_vec(data, MAX_QUORUMS)?,
    })
  }

  fn encode(&self, buf: &mut Vec<u8>) {
    self.version.encode(buf);
    self.base_block_hash.encode(buf);
    self.block_hash.encode(buf);
    self.total_transactions.encode(buf);
    codec::write_vec(&self.merkle_hashes, buf);
    codec::write_blob(&self.merkle_flags, buf);
    self.cb_tx.encode(buf);
    codec::write_vec(&self.deleted_mns, buf);
    codec::write_vec(&self.mn_list, buf);
    codec::write_vec(&self.deleted_quorums, buf);
    codec::write_vec(&self.new_quorums, buf);
    codec::write_vec(&self.quorum_cl_sigs, buf);
  }
}

crate::codec::impl_p2p!(MnListDiffPayload);

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
