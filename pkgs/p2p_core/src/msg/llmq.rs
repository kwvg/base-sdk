//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! LLMQ messages.

use crate::codec::{codec_p2p, impl_p2p};
use crate::macros::VersionedPayload;
use crate::msg::mn_list::MnListDiffPayload;
use crate::prelude::*;
use crate::{P2pDecodeError, ProtocolVersion};

use dash_primitives::{hash_impl, BlockHash, Commitment, DynBitset};
use dash_types::codec::{self, BaseCodec, DecodeError, EncodeBuf};
use dash_types::type_id::{TypeId, Unencodable};
use dash_types::{enum_map, impl_num, CompactSize};

/// Largest number of base block hashes in a `getqrinfo` message.
const MAX_BASE_BLOCK_HASHES: usize = 4096;

/// Recovered signature relay preference sent to a peer.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct QSendRecSigs {
  /// Whether the peer is to relay recovered signatures.
  pub send: bool,
}

codec_p2p!(QSendRecSigs { send });

/// Requests the quorum rotation info for a block.
#[derive(Clone, Debug, Eq, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct GetQrInfo {
  /// Blocks whose masternode lists the requester holds. A peer rejects more
  /// than 4096 hashes.
  pub base_block_hashes: Vec<BlockHash>,
  /// Block to build the rotation info at.
  pub block_request_hash: BlockHash,
  /// Whether to include the cycle four intervals back.
  pub extra_share: bool,
}

impl_p2p!(GetQrInfo);

impl BaseCodec for GetQrInfo {
  fn decode(data: &mut &[u8]) -> Result<Self, DecodeError> {
    Ok(Self {
      base_block_hashes: codec::decode_vec_limited(data, MAX_BASE_BLOCK_HASHES)?,
      block_request_hash: BlockHash::decode(data)?,
      extra_share: bool::decode(data)?,
    })
  }

  fn encode(&self, buf: &mut impl EncodeBuf) {
    self.base_block_hashes.encode(buf);
    self.block_request_hash.encode(buf);
    self.extra_share.encode(buf);
  }
}

hash_impl!(GetQrInfo);

enum_map! {
  /// How a quorum snapshot's skip list selects masternodes.
  #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, TypeId)]
  pub enum SnapshotSkipMode, i32, Unknown {
    /// No masternode is skipped.
    NoSkipping = 0 => "no_skipping",
    /// The skip list holds the skipped masternodes.
    SkippingEntries = 1 => "skipping_entries",
    /// The skip list holds the masternodes that are not skipped.
    NoSkippingEntries = 2 => "no_skipping_entries",
    /// Every masternode is skipped.
    AllSkipped = 3 => "all_skipped",
  }
}

impl_num!(SnapshotSkipMode, i32);

hash_impl!(SnapshotSkipMode);

/// Quorum membership at one rotation cycle.
#[derive(Clone, Debug, Eq, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct QuorumSnapshot {
  /// How `skip_list` is read.
  pub skip_list_mode: SnapshotSkipMode,
  /// One bit per masternode, set when the masternode is in the quorum.
  pub active_quorum_members: DynBitset,
  /// Masternodes that `skip_list_mode` selects. The first entry is an index
  /// into the sorted masternode list, and each later entry an offset from it.
  pub skip_list: Vec<i32>,
}

codec_p2p!(QuorumSnapshot {
  skip_list_mode,
  active_quorum_members,
  skip_list
});

/// Quorum snapshot and masternode list diff at one rotation cycle.
#[derive(Clone, Debug, Eq, Hash, PartialEq, Unencodable)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct QuorumCycle {
  /// Quorum membership at the cycle.
  pub snapshot: QuorumSnapshot,
  /// Masternode list diff to the cycle's work block.
  pub mn_list_diff: MnListDiffPayload,
}

/// Quorum rotation info, the response to a `getqrinfo`.
///
/// Every embedded diff is laid out at the protocol version negotiated with the
/// peer.
#[derive(Clone, Debug, Eq, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct QrInfo {
  /// Masternode list diff to the chain tip.
  pub mn_list_diff_tip: MnListDiffPayload,
  /// Masternode list diff to the work block of the requested cycle.
  pub mn_list_diff_h: MnListDiffPayload,
  /// Cycle one interval before the requested cycle.
  pub cycle_h_minus_c: QuorumCycle,
  /// Cycle two intervals before the requested cycle.
  pub cycle_h_minus_2c: QuorumCycle,
  /// Cycle three intervals before the requested cycle.
  pub cycle_h_minus_3c: QuorumCycle,
  /// Cycle four intervals before the requested cycle, present when the
  /// request asked for the extra share.
  pub cycle_h_minus_4c: Option<QuorumCycle>,
  /// Last commitment of each quorum index.
  pub last_commitment_per_index: Vec<Commitment>,
  /// Snapshots of the further cycles that `last_commitment_per_index` needs,
  /// in ascending height.
  pub quorum_snapshot_list: Vec<QuorumSnapshot>,
  /// Masternode list diffs to the work blocks of the cycles in
  /// `quorum_snapshot_list`.
  pub mn_list_diff_list: Vec<MnListDiffPayload>,
}

impl_p2p!(QrInfo);

impl BaseCodec for QrInfo {
  fn decode(data: &mut &[u8]) -> Result<Self, DecodeError> {
    Self::decode_at(data, ProtocolVersion::CURRENT)
  }

  fn encode(&self, buf: &mut impl EncodeBuf) {
    self.encode_at(buf, ProtocolVersion::CURRENT);
  }
}

hash_impl!(QrInfo);

impl QrInfo {
  /// Reads the rotation info as sent at protocol `version`.
  fn decode_at(data: &mut &[u8], version: ProtocolVersion) -> Result<Self, DecodeError> {
    let snapshot_c = QuorumSnapshot::decode(data)?;
    let snapshot_2c = QuorumSnapshot::decode(data)?;
    let snapshot_3c = QuorumSnapshot::decode(data)?;
    let mn_list_diff_tip = MnListDiffPayload::decode_versioned(data, version)?;
    let mn_list_diff_h = MnListDiffPayload::decode_versioned(data, version)?;
    let cycle_h_minus_c = QuorumCycle {
      snapshot: snapshot_c,
      mn_list_diff: MnListDiffPayload::decode_versioned(data, version)?,
    };
    let cycle_h_minus_2c = QuorumCycle {
      snapshot: snapshot_2c,
      mn_list_diff: MnListDiffPayload::decode_versioned(data, version)?,
    };
    let cycle_h_minus_3c = QuorumCycle {
      snapshot: snapshot_3c,
      mn_list_diff: MnListDiffPayload::decode_versioned(data, version)?,
    };
    let cycle_h_minus_4c = if bool::decode(data)? {
      Some(QuorumCycle {
        snapshot: QuorumSnapshot::decode(data)?,
        mn_list_diff: MnListDiffPayload::decode_versioned(data, version)?,
      })
    } else {
      None
    };
    let last_commitment_per_index = Vec::decode(data)?;
    let quorum_snapshot_list = Vec::decode(data)?;
    let mut mn_list_diff_list = Vec::new();
    for _ in 0..CompactSize::decode_len(data)? {
      mn_list_diff_list.push(MnListDiffPayload::decode_versioned(data, version)?);
    }
    Ok(Self {
      mn_list_diff_tip,
      mn_list_diff_h,
      cycle_h_minus_c,
      cycle_h_minus_2c,
      cycle_h_minus_3c,
      cycle_h_minus_4c,
      last_commitment_per_index,
      quorum_snapshot_list,
      mn_list_diff_list,
    })
  }

  /// Writes the rotation info as sent at protocol `version`.
  fn encode_at(&self, buf: &mut impl EncodeBuf, version: ProtocolVersion) {
    self.cycle_h_minus_c.snapshot.encode(buf);
    self.cycle_h_minus_2c.snapshot.encode(buf);
    self.cycle_h_minus_3c.snapshot.encode(buf);
    self.mn_list_diff_tip.encode_versioned(buf, version);
    self.mn_list_diff_h.encode_versioned(buf, version);
    self.cycle_h_minus_c.mn_list_diff.encode_versioned(buf, version);
    self.cycle_h_minus_2c.mn_list_diff.encode_versioned(buf, version);
    self.cycle_h_minus_3c.mn_list_diff.encode_versioned(buf, version);
    self.cycle_h_minus_4c.is_some().encode(buf);
    if let Some(cycle) = &self.cycle_h_minus_4c {
      cycle.snapshot.encode(buf);
      cycle.mn_list_diff.encode_versioned(buf, version);
    }
    self.last_commitment_per_index.encode(buf);
    self.quorum_snapshot_list.encode(buf);
    CompactSize::from(self.mn_list_diff_list.len()).encode(buf);
    for diff in &self.mn_list_diff_list {
      diff.encode_versioned(buf, version);
    }
  }
}

impl VersionedPayload for QrInfo {
  fn decode_versioned(payload: &[u8], version: ProtocolVersion) -> Result<Self, P2pDecodeError> {
    let mut data = payload;
    let info = Self::decode_at(&mut data, version)?;
    if !data.is_empty() {
      return Err(DecodeError::TrailingBytes { remaining: data.len() }.into());
    }
    Ok(info)
  }

  fn encode_versioned(&self, buf: &mut Vec<u8>, version: ProtocolVersion) {
    self.encode_at(buf, version);
  }
}

#[cfg(test)]
mod tests {
  use super::{GetQrInfo, QSendRecSigs, QrInfo, QuorumCycle, QuorumSnapshot, SnapshotSkipMode, MAX_BASE_BLOCK_HASHES};
  use crate::msg::mn_list::MnListDiffPayload;
  use crate::prelude::*;
  use crate::{CommandString, P2pDecodeError, P2pMsg, ProtocolVersion};

  use dash_primitives::{BlockHash, DynBitset, PartialMerkleTree, Transaction, TxType};
  use dash_types::codec::BaseCodec;
  use dash_types::Numeric;
  use rstest::rstest;

  #[rstest]
  #[case::zero(0x00, false)]
  #[case::one(0x01, true)]
  #[case::other(0x02, true)]
  fn decodes_the_flag_byte(#[case] byte: u8, #[case] send: bool) {
    assert_eq!(
      P2pMsg::decode_payload(&CommandString::QSENDRECSIGS, &[byte]),
      Ok(P2pMsg::QSendRecSigs(QSendRecSigs { send }))
    );
  }

  #[rstest]
  #[case::off(false, 0x00)]
  #[case::on(true, 0x01)]
  fn encodes_one_byte(#[case] send: bool, #[case] byte: u8) {
    let mut buf = alloc::vec::Vec::new();
    P2pMsg::QSendRecSigs(QSendRecSigs { send }).encode_payload(&mut buf);
    assert_eq!(buf, [byte]);
  }

  #[rstest]
  fn rejects_an_empty_payload() {
    assert!(matches!(
      P2pMsg::decode_payload(&CommandString::QSENDRECSIGS, &[]),
      Err(P2pDecodeError::Consensus(_))
    ));
  }

  fn getqrinfo(count: usize) -> GetQrInfo {
    GetQrInfo {
      base_block_hashes: vec![BlockHash::from_lendian([0x11; 32]); count],
      block_request_hash: BlockHash::from_lendian([0x22; 32]),
      extra_share: true,
    }
  }

  #[rstest]
  fn getqrinfo_wire_is_bases_request_hash_and_flag() {
    let mut expected = vec![0x01];
    expected.extend([0x11; 32]);
    expected.extend([0x22; 32]);
    expected.push(0x01);
    let mut buf = Vec::new();
    P2pMsg::GetQrInfo(getqrinfo(1)).encode_payload(&mut buf);
    assert_eq!(buf, expected);
    assert_eq!(
      P2pMsg::decode_payload(&CommandString::GETQRINFO, &expected),
      Ok(P2pMsg::GetQrInfo(getqrinfo(1)))
    );
  }

  #[rstest]
  #[case::empty(0, true)]
  #[case::at_limit(MAX_BASE_BLOCK_HASHES, true)]
  #[case::past_limit(MAX_BASE_BLOCK_HASHES + 1, false)]
  fn getqrinfo_carries_at_most_4096_base_hashes(#[case] count: usize, #[case] accepted: bool) {
    let mut payload = Vec::new();
    P2pMsg::GetQrInfo(getqrinfo(count)).encode_payload(&mut payload);
    let decoded = P2pMsg::decode_payload(&CommandString::GETQRINFO, &payload);
    if accepted {
      assert_eq!(decoded, Ok(P2pMsg::GetQrInfo(getqrinfo(count))));
    } else {
      assert!(matches!(decoded, Err(P2pDecodeError::Consensus(_))));
    }
  }

  #[rstest]
  fn getqrinfo_rejects_trailing_bytes() {
    let mut payload = Vec::new();
    P2pMsg::GetQrInfo(getqrinfo(1)).encode_payload(&mut payload);
    payload.push(0);
    assert!(matches!(
      P2pMsg::decode_payload(&CommandString::GETQRINFO, &payload),
      Err(P2pDecodeError::Consensus(_))
    ));
  }

  #[rstest]
  fn quorum_snapshot_wire_is_mode_members_and_skip_list() {
    let item = QuorumSnapshot {
      skip_list_mode: SnapshotSkipMode::SkippingEntries,
      active_quorum_members: DynBitset {
        num_bits: 10,
        data: vec![0x55, 0x01],
      },
      skip_list: vec![10, -1],
    };
    let wire = [
      0x01, 0x00, 0x00, 0x00, 0x0a, 0x55, 0x01, 0x02, 0x0a, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff,
    ];
    let mut buf = Vec::new();
    item.encode(&mut buf);
    assert_eq!(buf, wire);
    assert_eq!(QuorumSnapshot::decode(&mut wire.as_slice()), Ok(item));
  }

  #[rstest]
  #[case::no_skipping(0, SnapshotSkipMode::NoSkipping)]
  #[case::skipping_entries(1, SnapshotSkipMode::SkippingEntries)]
  #[case::no_skipping_entries(2, SnapshotSkipMode::NoSkippingEntries)]
  #[case::all_skipped(3, SnapshotSkipMode::AllSkipped)]
  #[case::unknown(4, SnapshotSkipMode::Unknown(4))]
  #[case::negative(-1, SnapshotSkipMode::Unknown(-1))]
  fn skip_modes_follow_the_reference_codes(#[case] code: i32, #[case] mode: SnapshotSkipMode) {
    assert_eq!(SnapshotSkipMode::from_base(code), mode);
    assert_eq!(mode.to_base(), code);
  }

  fn snapshot(entry: i32) -> QuorumSnapshot {
    QuorumSnapshot {
      skip_list_mode: SnapshotSkipMode::SkippingEntries,
      active_quorum_members: DynBitset {
        num_bits: 3,
        data: vec![0x05],
      },
      skip_list: vec![entry],
    }
  }

  fn diff(hash_byte: u8) -> MnListDiffPayload {
    MnListDiffPayload {
      version: 1,
      base_block_hash: BlockHash::from_lendian([0x01; 32]),
      block_hash: BlockHash::from_lendian([hash_byte; 32]),
      cb_tx_merkle_tree: PartialMerkleTree::default(),
      cb_tx: Transaction {
        version: 3,
        tx_type: TxType::Spend,
        inputs: Vec::new(),
        outputs: Vec::new(),
        lock_time: 0,
        extra_payload: Vec::new(),
      },
      deleted_mns: Vec::new(),
      mn_list: Vec::new(),
      deleted_quorums: Vec::new(),
      new_quorums: Vec::new(),
      quorum_cl_sigs: Vec::new(),
    }
  }

  fn cycle(n: u8) -> QuorumCycle {
    QuorumCycle {
      snapshot: snapshot(i32::from(n)),
      mn_list_diff: diff(n),
    }
  }

  fn qrinfo(extra_share: bool) -> QrInfo {
    QrInfo {
      mn_list_diff_tip: diff(0xa0),
      mn_list_diff_h: diff(0xa1),
      cycle_h_minus_c: cycle(1),
      cycle_h_minus_2c: cycle(2),
      cycle_h_minus_3c: cycle(3),
      cycle_h_minus_4c: extra_share.then(|| cycle(4)),
      last_commitment_per_index: Vec::new(),
      quorum_snapshot_list: vec![snapshot(5)],
      mn_list_diff_list: vec![diff(5)],
    }
  }

  /// Builds the wire image from the field encodings, with every diff laid out
  /// at `version`.
  fn qrinfo_layout(info: &QrInfo, version: ProtocolVersion) -> Vec<u8> {
    let mut out = Vec::new();
    info.cycle_h_minus_c.snapshot.encode(&mut out);
    info.cycle_h_minus_2c.snapshot.encode(&mut out);
    info.cycle_h_minus_3c.snapshot.encode(&mut out);
    for diff in [
      &info.mn_list_diff_tip,
      &info.mn_list_diff_h,
      &info.cycle_h_minus_c.mn_list_diff,
      &info.cycle_h_minus_2c.mn_list_diff,
      &info.cycle_h_minus_3c.mn_list_diff,
    ] {
      diff.encode_versioned(&mut out, version);
    }
    match &info.cycle_h_minus_4c {
      Some(cycle) => {
        out.push(0x01);
        cycle.snapshot.encode(&mut out);
        cycle.mn_list_diff.encode_versioned(&mut out, version);
      }
      None => out.push(0x00),
    }
    out.push(0x00);
    out.push(0x01);
    info.quorum_snapshot_list[0].encode(&mut out);
    out.push(0x01);
    info.mn_list_diff_list[0].encode_versioned(&mut out, version);
    out
  }

  #[rstest]
  #[case::min_peer(ProtocolVersion::MIN_PEER, false)]
  #[case::smnle_versioned(ProtocolVersion::SMNLE_VERSIONED, true)]
  #[case::current(ProtocolVersion::CURRENT, false)]
  #[case::current_extra_share(ProtocolVersion::CURRENT, true)]
  fn qrinfo_lays_out_its_diffs_at_the_peer_version(#[case] version: ProtocolVersion, #[case] extra_share: bool) {
    let info = qrinfo(extra_share);
    let raw = qrinfo_layout(&info, version);
    let mut buf = Vec::new();
    P2pMsg::QrInfo(Box::new(info.clone())).encode_payload_with_version(&mut buf, version);
    assert_eq!(buf, raw);
    assert_eq!(
      P2pMsg::decode_payload_with_version(&CommandString::QRINFO, &raw, version),
      Ok(P2pMsg::QrInfo(Box::new(info)))
    );
  }

  #[rstest]
  fn qrinfo_diff_layouts_differ_across_the_version_order_boundary() {
    let info = qrinfo(false);
    assert_ne!(
      qrinfo_layout(&info, ProtocolVersion::SMNLE_VERSIONED),
      qrinfo_layout(&info, ProtocolVersion::MNLISTDIFF_VERSION_ORDER)
    );
  }

  #[rstest]
  fn qrinfo_rejects_trailing_bytes() {
    let mut payload = qrinfo_layout(&qrinfo(false), ProtocolVersion::CURRENT);
    payload.push(0);
    assert!(matches!(
      P2pMsg::decode_payload(&CommandString::QRINFO, &payload),
      Err(P2pDecodeError::Consensus(_))
    ));
  }
}
