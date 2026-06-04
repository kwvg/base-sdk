//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Simplified masternode list types for `getmnlistd`/`mnlistdiff`.

use crate::encode::{encode_compact_size, BufferDecoder, VecEncoder, WireDecodeError, MAX_P2P_PAYLOAD};
use crate::prelude::*;

use bitcoin_consensus_encoding as encoding;
use dash_primitives::payload::Commitment;
use dash_primitives::wire;
use dash_primitives::{BlockHash, CService, LlmqType, MnType, Transaction, TxHash};
use dash_script::KeyId;
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
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
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
  #[cfg_attr(feature = "serde", serde(with = "dash_types::serialize::uint::w16"))]
  pub mn_type: MnType,
  /// Platform HTTP port (Evo masternodes only).
  pub platform_http_port: Option<u16>,
  /// Platform node ID (Evo masternodes only).
  pub platform_node_id: Option<PlatformNodeId>,
}

impl SimplifiedMnListEntry {
  /// Decodes an entry from the wire format.
  pub(crate) fn decode(sl: &mut &[u8]) -> Result<Self, WireDecodeError> {
    let version = wire::read_u16_le(sl)?;
    let pro_reg_tx_hash = TxHash::from_bytes(wire::read_array(sl)?);
    let confirmed_hash = BlockHash::from_bytes(wire::read_array(sl)?);
    let service = wire::read_cservice(sl)?;
    let operator_key = BlsPublicKeyBytes(wire::read_array(sl)?);
    let voting_key_id = KeyId(wire::read_array(sl)?);
    let is_valid = wire::read_bool(sl)?;

    // nType is gated by the entry's version
    let mn_type = if version >= 2 {
      MnType::from_u16(wire::read_u16_le(sl)?)
    } else {
      MnType::Regular
    };

    let (platform_http_port, platform_node_id) = if mn_type == MnType::Evo {
      let port = wire::read_u16_le(sl)?;
      let node_id = PlatformNodeId(wire::read_array(sl)?);
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

  /// Encodes this entry to the wire format.
  pub(crate) fn encode(&self, buf: &mut Vec<u8>) {
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
      buf.extend_from_slice(&self.mn_type.to_u16().to_le_bytes());
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
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct DeletedQuorum {
  /// LLMQ type.
  #[cfg_attr(feature = "serde", serde(with = "dash_types::serialize::uint::w8"))]
  pub llmq_type: LlmqType,
  /// Quorum hash.
  pub hash: BlockHash,
}

/// Chainlock signature entry in the MN list diff.
///
/// Each entry maps a BLS signature to the indices (within
/// `new_quorums`) of the quorums it covers.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct QuorumClSig {
  /// BLS signature.
  pub sig: BlsSignatureBytes,
  /// Indices into the `new_quorums` vector.
  pub index_set: Vec<u16>,
}

/// Full masternode list diff payload.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
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

impl MnListDiffPayload {
  pub(crate) fn decode_from_slice(data: &[u8]) -> Result<Self, WireDecodeError> {
    let sl = &mut &data[..];
    let version = wire::read_u16_le(sl)?;
    let base_block_hash = BlockHash::from_bytes(wire::read_array(sl)?);
    let block_hash = BlockHash::from_bytes(wire::read_array(sl)?);
    let total_transactions = wire::read_u32_le(sl)?;

    let mh_count = wire::read_compact_size(sl, MAX_MERKLE)?;
    let mut merkle_hashes = Vec::with_capacity(mh_count);
    for _ in 0..mh_count {
      merkle_hashes.push(TxHash::from_bytes(wire::read_array(sl)?));
    }

    let mf_count = wire::read_compact_size(sl, MAX_MERKLE_FLAGS)?;
    let merkle_flags = wire::read_bytes(sl, mf_count)?.to_vec();

    // Transaction uses encoding::Decodable. Decode from remaining bytes.
    let cb_tx = encoding::decode_from_slice_unbounded::<Transaction>(sl)
      .map_err(|e| WireDecodeError(format!("transaction decode: {e}")))?;

    let del_count = wire::read_compact_size(sl, MAX_DELETED_MNS)?;
    let mut deleted_mns = Vec::with_capacity(del_count);
    for _ in 0..del_count {
      deleted_mns.push(TxHash::from_bytes(wire::read_array(sl)?));
    }

    let mn_count = wire::read_compact_size(sl, MAX_MN_LIST)?;
    let mut mn_list = Vec::with_capacity(mn_count);
    for _ in 0..mn_count {
      mn_list.push(SimplifiedMnListEntry::decode(sl)?);
    }

    let dq_count = wire::read_compact_size(sl, MAX_QUORUMS)?;
    let mut deleted_quorums = Vec::with_capacity(dq_count);
    for _ in 0..dq_count {
      let llmq_type = LlmqType::from_u8(wire::read_u8(sl)?);
      let hash = BlockHash::from_bytes(wire::read_array(sl)?);
      deleted_quorums.push(DeletedQuorum { llmq_type, hash });
    }

    let nq_count = wire::read_compact_size(sl, MAX_QUORUMS)?;
    let mut new_quorums = Vec::with_capacity(nq_count);
    for _ in 0..nq_count {
      let commitment = Commitment::decode_inner(sl).map_err(|e| WireDecodeError(format!("commitment decode: {e}")))?;
      new_quorums.push(commitment);
    }

    // Chainlock signatures (protocol >= 70230).
    let cl_count = wire::read_compact_size(sl, MAX_QUORUMS)?;
    let mut quorum_cl_sigs = Vec::with_capacity(cl_count);
    for _ in 0..cl_count {
      let sig = BlsSignatureBytes(wire::read_array(sl)?);
      let idx_count = wire::read_compact_size(sl, MAX_QUORUMS)?;
      let mut index_set = Vec::with_capacity(idx_count);
      for _ in 0..idx_count {
        index_set.push(wire::read_u16_le(sl)?);
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

  fn encode_to_vec_buf(&self) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(&self.version.to_le_bytes());
    buf.extend_from_slice(&self.base_block_hash.to_bytes());
    buf.extend_from_slice(&self.block_hash.to_bytes());
    buf.extend_from_slice(&self.total_transactions.to_le_bytes());

    encode_compact_size(self.merkle_hashes.len(), &mut buf);
    for h in &self.merkle_hashes {
      buf.extend_from_slice(&h.to_bytes());
    }

    encode_compact_size(self.merkle_flags.len(), &mut buf);
    buf.extend_from_slice(&self.merkle_flags);

    let tx_bytes = encoding::encode_to_vec(&self.cb_tx);
    buf.extend_from_slice(&tx_bytes);

    encode_compact_size(self.deleted_mns.len(), &mut buf);
    for h in &self.deleted_mns {
      buf.extend_from_slice(&h.to_bytes());
    }

    encode_compact_size(self.mn_list.len(), &mut buf);
    for entry in &self.mn_list {
      entry.encode(&mut buf);
    }

    encode_compact_size(self.deleted_quorums.len(), &mut buf);
    for dq in &self.deleted_quorums {
      buf.push(dq.llmq_type.to_u8());
      buf.extend_from_slice(&dq.hash.to_bytes());
    }

    encode_compact_size(self.new_quorums.len(), &mut buf);
    for q in &self.new_quorums {
      q.encode(&mut buf);
    }

    encode_compact_size(self.quorum_cl_sigs.len(), &mut buf);
    for cl in &self.quorum_cl_sigs {
      buf.extend_from_slice(&cl.sig.0);
      encode_compact_size(cl.index_set.len(), &mut buf);
      for &idx in &cl.index_set {
        buf.extend_from_slice(&idx.to_le_bytes());
      }
    }

    buf
  }
}

impl encoding::Encodable for MnListDiffPayload {
  type Encoder<'e> = VecEncoder;
  fn encoder(&self) -> Self::Encoder<'_> {
    VecEncoder::new(self.encode_to_vec_buf())
  }
}

impl encoding::Decodable for MnListDiffPayload {
  type Decoder = BufferDecoder<MnListDiffPayload, WireDecodeError>;
  fn decoder() -> Self::Decoder {
    BufferDecoder::new(MnListDiffPayload::decode_from_slice, MAX_P2P_PAYLOAD)
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
