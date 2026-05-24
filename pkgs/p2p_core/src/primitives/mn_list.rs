//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Simplified masternode list types for `getmnlistd`/`mnlistdiff`.

use crate::encode::MAX_P2P_PAYLOAD;
use crate::prelude::*;

use bitcoin_consensus_encoding as encoding;
use dash_primitives::payload::Commitment;
use dash_primitives::codec::{BufferDecoder, VecEncoder};
use dash_primitives::wire;
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
    let version = codec::read_u16_le(data)?;
    let pro_reg_tx_hash = TxHash::from_bytes(codec::take(data)?);
    let confirmed_hash = BlockHash::from_bytes(codec::take(data)?);
    let service = wire::read_cservice(data)?;
    let operator_key = BlsPublicKeyBytes(codec::take(data)?);
    let voting_key_id = KeyId(codec::take(data)?);
    let is_valid = codec::read_bool(data)?;

    // nType is gated by the entry's version
    let mn_type = if version >= 2 {
      MnType::from_base(codec::read_u16_le(data)?)
    } else {
      MnType::Regular
    };

    let (platform_http_port, platform_node_id) = if mn_type == MnType::Evo {
      let port = codec::read_u16_le(data)?;
      let node_id = PlatformNodeId(codec::take(data)?);
      (Some(port), Some(node_id))
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
    buf.extend_from_slice(&self.version.to_le_bytes());
    buf.extend_from_slice(&self.pro_reg_tx_hash.to_bytes());
    buf.extend_from_slice(&self.confirmed_hash.to_bytes());
    buf.extend_from_slice(&self.service.addr);
    buf.extend_from_slice(&self.service.port.to_be_bytes());
    buf.extend_from_slice(&self.operator_key.0);
    buf.extend_from_slice(&self.voting_key_id.0);
    buf.push(u8::from(self.is_valid));
    // nType and platform fields are gated by the entry's version
    if self.version >= 2 {
      buf.extend_from_slice(&self.mn_type.to_base().to_le_bytes());
      if self.mn_type == MnType::Evo {
        buf.extend_from_slice(&self.platform_http_port.unwrap_or(0).to_le_bytes());
        buf.extend_from_slice(self.platform_node_id.as_ref().map_or(&[0u8; 20], |n| &n.0));
      }
    }
  }
}

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
    let version = codec::read_u16_le(data)?;
    let base_block_hash = BlockHash::from_bytes(codec::take(data)?);
    let block_hash = BlockHash::from_bytes(codec::take(data)?);
    let total_transactions = codec::read_u32_le(data)?;

    let mh_count = codec::read_compact_size(data, MAX_MERKLE)?;
    let mut merkle_hashes = Vec::with_capacity(mh_count);
    for _ in 0..mh_count {
      merkle_hashes.push(TxHash::from_bytes(codec::take(data)?));
    }

    let mf_count = codec::read_compact_size(data, MAX_MERKLE_FLAGS)?;
    let merkle_flags = codec::read_bytes(data, mf_count)?.to_vec();

    // Transaction uses encoding::Decodable. Decode from remaining bytes.
    let cb_tx = encoding::decode_from_slice_unbounded::<Transaction>(data).map_err(|_| DecodeError::Eof {
      needed: 1,
      remaining: 0,
    })?;

    let del_count = codec::read_compact_size(data, MAX_DELETED_MNS)?;
    let mut deleted_mns = Vec::with_capacity(del_count);
    for _ in 0..del_count {
      deleted_mns.push(TxHash::from_bytes(codec::take(data)?));
    }

    let mn_count = codec::read_compact_size(data, MAX_MN_LIST)?;
    let mut mn_list = Vec::with_capacity(mn_count);
    for _ in 0..mn_count {
      mn_list.push(Codec::decode(data)?);
    }

    let dq_count = codec::read_compact_size(data, MAX_QUORUMS)?;
    let mut deleted_quorums = Vec::with_capacity(dq_count);
    for _ in 0..dq_count {
      let llmq_type = LlmqType::from_base(codec::read_u8(data)?);
      let hash = BlockHash::from_bytes(codec::take(data)?);
      deleted_quorums.push(DeletedQuorum { llmq_type, hash });
    }

    let nq_count = codec::read_compact_size(data, MAX_QUORUMS)?;
    let mut new_quorums = Vec::with_capacity(nq_count);
    for _ in 0..nq_count {
      let commitment: Commitment = Codec::decode(data).map_err(|_| DecodeError::Eof {
        needed: 1,
        remaining: 0,
      })?;
      new_quorums.push(commitment);
    }

    // Chainlock signatures (protocol >= 70230).
    let cl_count = codec::read_compact_size(data, MAX_QUORUMS)?;
    let mut quorum_cl_sigs = Vec::with_capacity(cl_count);
    for _ in 0..cl_count {
      let sig = BlsSignatureBytes(codec::take(data)?);
      let idx_count = codec::read_compact_size(data, MAX_QUORUMS)?;
      let mut index_set = Vec::with_capacity(idx_count);
      for _ in 0..idx_count {
        index_set.push(codec::read_u16_le(data)?);
      }
      quorum_cl_sigs.push(QuorumClSig { sig, index_set });
    }

    Ok(Self {
      version,
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

  fn encode(&self, buf: &mut Vec<u8>) {
    buf.extend_from_slice(&self.version.to_le_bytes());
    buf.extend_from_slice(&self.base_block_hash.to_bytes());
    buf.extend_from_slice(&self.block_hash.to_bytes());
    buf.extend_from_slice(&self.total_transactions.to_le_bytes());

    codec::write_compact_size(self.merkle_hashes.len(), buf);
    for h in &self.merkle_hashes {
      buf.extend_from_slice(&h.to_bytes());
    }

    codec::write_compact_size(self.merkle_flags.len(), buf);
    buf.extend_from_slice(&self.merkle_flags);

    let tx_bytes = encoding::encode_to_vec(&self.cb_tx);
    buf.extend_from_slice(&tx_bytes);

    codec::write_compact_size(self.deleted_mns.len(), buf);
    for h in &self.deleted_mns {
      buf.extend_from_slice(&h.to_bytes());
    }

    codec::write_compact_size(self.mn_list.len(), buf);
    for entry in &self.mn_list {
      Codec::encode(entry, buf);
    }

    codec::write_compact_size(self.deleted_quorums.len(), buf);
    for dq in &self.deleted_quorums {
      buf.push(dq.llmq_type.to_base());
      buf.extend_from_slice(&dq.hash.to_bytes());
    }

    codec::write_compact_size(self.new_quorums.len(), buf);
    for q in &self.new_quorums {
      Codec::encode(q, buf);
    }

    codec::write_compact_size(self.quorum_cl_sigs.len(), buf);
    for cl in &self.quorum_cl_sigs {
      buf.extend_from_slice(&cl.sig.0);
      codec::write_compact_size(cl.index_set.len(), buf);
      for &idx in &cl.index_set {
        buf.extend_from_slice(&idx.to_le_bytes());
      }
    }
  }
}

impl encoding::Encodable for MnListDiffPayload {
  type Encoder<'e> = VecEncoder;
  fn encoder(&self) -> Self::Encoder<'_> {
    let mut buf = Vec::new();
    Codec::encode(self, &mut buf);
    VecEncoder::new(buf)
  }
}

impl encoding::Decodable for MnListDiffPayload {
  type Decoder = BufferDecoder<MnListDiffPayload, DecodeError>;
  fn decoder() -> Self::Decoder {
    BufferDecoder::new(<Self as Codec>::decode, MAX_P2P_PAYLOAD)
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
