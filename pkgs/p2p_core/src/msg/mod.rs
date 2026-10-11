//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! P2P message types and dispatch.

mod addr;
mod bloom;
mod coinjoin;
mod gov;
mod headers;
mod headers2;
mod inv;
mod llmq;
mod mn_list;
mod ping;
mod sync;
mod version;

use crate::command::CommandString;
use crate::prelude::*;
use crate::short_id::ShortId;

use dash_primitives::{ChainLockSig, GovObject, GovVote, InstantSendLock};
use dash_types::type_id::Unencodable;

pub use addr::{Addr, AddrV2Entry, AddrV2Msg, TimestampedAddr};
pub use bloom::{BloomFilter, BloomFilterInvalid};
pub use coinjoin::SendDsq;
pub use gov::GovSync;
pub use headers::{GetHeaders, Headers, NonContinuousHeaders};
pub use headers2::{CompressionState, GetHeaders2, Headers2};
pub use inv::{GetData, Inv, InvType, Inventory, NotFound};
pub use llmq::{GetQrInfo, QSendRecSigs};
pub use mn_list::{
  sml_merkle_root, DeletedQuorum, GetMnListDiff, MnListDiff, MnListDiffInvalid, MnListDiffPayload,
  NetInfoVersionMismatch, QuorumClSig, SimplifiedMnListEntry, SmlEntryInvalid,
};
pub use ping::{Ping, Pong};
pub use sync::{SyncItemId, SyncStatusCount};
pub use version::{ServiceFlags, UserAgent, UserAgentTooLong, Version, VersionAddr};

unversioned_payload!(
  Addr,
  AddrV2Msg,
  ChainLockSig,
  GetData,
  GetHeaders,
  GetHeaders2,
  GetMnListDiff,
  GetQrInfo,
  GovObject,
  GovSync,
  GovVote,
  Headers,
  InstantSendLock,
  Inv,
  Ping,
  Pong,
  QSendRecSigs,
  SendDsq,
  SyncStatusCount,
  Version,
);

define_p2p! {
  parsed {
    /// Protocol version exchange.
    Version(Version) => VERSION "version",
    /// V1 address list.
    Addr(Addr) => ADDR "addr" @ 1,
    /// Request specific inventory.
    GetData(GetData) => GETDATA "getdata" @ 11,
    /// Request block headers.
    GetHeaders(GetHeaders) => GETHEADERS "getheaders" @ 12,
    /// Block headers.
    Headers(Headers) => HEADERS "headers" @ 13,
    /// Inventory announcement.
    Inv(Inv) => INV "inv" @ 14,
    /// Inventory not found.
    NotFound(NotFound) => NOTFOUND "notfound" @ 17,
    /// Keepalive request.
    Ping(Ping) => PING "ping" @ 18,
    /// Keepalive response.
    Pong(Pong) => PONG "pong" @ 19,
    /// BIP155 V2 address list.
    AddrV2(AddrV2Msg) => ADDRV2 "addrv2" @ 28,
    /// Signal CoinJoin queue relay.
    SendDsq(SendDsq) => SENDDSQ "senddsq" @ 130,
    /// Sync status count.
    Ssc(SyncStatusCount) => SSC "ssc" @ 139,
    /// Governance sync request.
    GovSync(GovSync) => GOVSYNC "govsync" @ 140,
    /// Governance object.
    GovObj(GovObject) => GOVOBJ "govobj" @ 141,
    /// Governance vote.
    GovObjVote(GovVote) => GOVOBJVOTE "govobjvote" @ 142,
    /// Request MN list diff.
    GetMnListDiff(GetMnListDiff) => GETMNLISTD "getmnlistd" @ 143,
    /// MN list diff.
    MnListDiff(MnListDiff) => MNLISTDIFF "mnlistdiff" @ 144,
    /// LLMQ: send recovered signatures.
    QSendRecSigs(QSendRecSigs) => QSENDRECSIGS "qsendrecsigs" @ 145,
    /// ChainLock signature.
    ClSig(ChainLockSig) => CLSIG "clsig" @ 160,
    /// InstantSend deterministic lock.
    IsdLock(InstantSendLock) => ISDLOCK "isdlock" @ 161,
    /// Request compressed block headers.
    GetHeaders2(GetHeaders2) => GETHEADERS2 "getheaders2" @ 163,
    /// Compressed block headers.
    Headers2(Headers2) => HEADERS2 "headers2" @ 165,
    /// Request quorum rotation info.
    GetQrInfo(GetQrInfo) => GETQRINFO "getqrinfo" @ 166,
  }

  parsed_empty {
    /// Request peer addresses.
    GetAddr => GETADDR "getaddr",
    /// Signal addrv2 support.
    SendAddrV2 => SENDADDRV2 "sendaddrv2",
    /// Prefer unsolicited header announcements.
    SendHeaders => SENDHEADERS "sendheaders",
    /// Version acknowledgement.
    Verack => VERACK "verack",
    /// BIP37: clear bloom filter.
    FilterClear => FILTERCLEAR "filterclear" @ 7,
    /// Request mempool contents.
    Mempool => MEMPOOL "mempool" @ 15,
    /// Request active sporks.
    GetSporks => GETSPORKS "getsporks" @ 129,
    /// LLMQ: watch quorums.
    QWatch => QWATCH "qwatch" @ 151,
    /// Prefer compressed header announcements.
    SendHeaders2 => SENDHEADERS2 "sendheaders2" @ 164,
  }

  stub {
    /// BIP330: transaction reconciliation.
    SendTxRcncl => SENDTXRCNCL "sendtxrcncl",
    /// Block data.
    Block => BLOCK "block" @ 2,
    /// BIP152: compact block transactions.
    BlockTxn => BLOCKTXN "blocktxn" @ 3,
    /// BIP152: compact block.
    CmpctBlock => CMPCTBLOCK "cmpctblock" @ 4,
    /// BIP37: add data to bloom filter.
    FilterAdd => FILTERADD "filteradd" @ 6,
    /// BIP37: load bloom filter.
    FilterLoad => FILTERLOAD "filterload" @ 8,
    /// Request block hashes.
    GetBlocks => GETBLOCKS "getblocks" @ 9,
    /// BIP152: request compact block transactions.
    GetBlockTxn => GETBLOCKTXN "getblocktxn" @ 10,
    /// BIP37: filtered block.
    MerkleBlock => MERKLEBLOCK "merkleblock" @ 16,
    /// BIP152: signal compact block support.
    SendCmpct => SENDCMPCT "sendcmpct" @ 20,
    /// Transaction.
    Tx => TX "tx" @ 21,
    /// Request compact filters.
    GetCFilters => GETCFILTERS "getcfilters" @ 22,
    /// Compact block filter.
    CFilter => CFILTER "cfilter" @ 23,
    /// Request compact filter headers.
    GetCFHeaders => GETCFHEADERS "getcfheaders" @ 24,
    /// Compact filter headers.
    CFHeaders => CFHEADERS "cfheaders" @ 25,
    /// Request compact filter checkpoints.
    GetCFCheckpt => GETCFCHECKPT "getcfcheckpt" @ 26,
    /// Compact filter checkpoints.
    CFCheckpt => CFCHECKPT "cfcheckpt" @ 27,
    /// Spork broadcast/request.
    Spork => SPORK "spork" @ 128,
    /// CoinJoin: accept denomination.
    Dsa => DSA "dsa" @ 131,
    /// CoinJoin: submit inputs.
    Dsi => DSI "dsi" @ 132,
    /// CoinJoin: final transaction.
    Dsf => DSF "dsf" @ 133,
    /// CoinJoin: sign final transaction.
    Dss => DSS "dss" @ 134,
    /// CoinJoin: complete.
    Dsc => DSC "dsc" @ 135,
    /// CoinJoin: status update.
    Dssu => DSSU "dssu" @ 136,
    /// CoinJoin: broadcast transaction.
    Dstx => DSTX "dstx" @ 137,
    /// CoinJoin: queue entry.
    Dsq => DSQ "dsq" @ 138,
    /// LLMQ: final commitment.
    QfCommit => QFCOMMIT "qfcommit" @ 146,
    /// LLMQ: contribution.
    QContrib => QCONTRIB "qcontrib" @ 147,
    /// LLMQ: complaint.
    QComplaint => QCOMPLAINT "qcomplaint" @ 148,
    /// LLMQ: justification.
    QJustify => QJUSTIFY "qjustify" @ 149,
    /// LLMQ: premature commitment.
    QpCommit => QPCOMMIT "qpcommit" @ 150,
    /// LLMQ: signing session announcement.
    QSigSesAnn => QSIGSESANN "qsigsesann" @ 152,
    /// LLMQ: signature shares inventory.
    QSigsInv => QSIGSINV "qsigsinv" @ 153,
    /// LLMQ: request signature shares.
    QGetSigs => QGETSIGS "qgetsigs" @ 154,
    /// LLMQ: batched signature shares.
    QbSigs => QBSIGS "qbsigs" @ 155,
    /// LLMQ: recovered signature.
    QSigRec => QSIGREC "qsigrec" @ 156,
    /// LLMQ: single signature share.
    QSigShare => QSIGSHARE "qsigshare" @ 157,
    /// LLMQ: request quorum data.
    QGetData => QGETDATA "qgetdata" @ 158,
    /// LLMQ: quorum data.
    QData => QDATA "qdata" @ 159,
    /// Masternode authentication.
    MnAuth => MNAUTH "mnauth" @ 162,
    /// Quorum rotation info.
    QrInfo => QRINFO "qrinfo" @ 167,
    /// DIP-0031: platform ban.
    PlatformBan => PLATFORMBAN "platformban" @ 168,
  }

  stub_empty {}
}

#[cfg(test)]
mod tests {
  use super::{CommandString, P2pMsg};
  use crate::prelude::*;
  use crate::P2pDecodeError;

  use dash_pkc::bls::BlsSigBytes;
  use dash_primitives::{BlockHash, ChainLockSig, InstantSendLock, OutPoint, TxHash};
  use dash_types::Numeric;
  use rstest::rstest;

  fn clsig_payload() -> Vec<u8> {
    let mut payload = vec![0x64, 0x00, 0x00, 0x00];
    payload.extend([0x11; 32]);
    payload.extend([0xab; 96]);
    payload
  }

  #[rstest]
  fn clsig_is_a_chainlock_sig() {
    let item = ChainLockSig {
      height: 100,
      block_hash: BlockHash::from_lendian([0x11; 32]),
      sig: BlsSigBytes::from_bytes([0xab; 96]),
    };
    let msg = P2pMsg::decode_payload(&CommandString::CLSIG, &clsig_payload());
    assert_eq!(msg, Ok(P2pMsg::ClSig(item.clone())));
    let mut buf = Vec::new();
    P2pMsg::ClSig(item).encode_payload(&mut buf);
    assert_eq!(buf, clsig_payload());
  }

  #[rstest]
  #[case::truncated(-1)]
  #[case::trailing(1)]
  fn clsig_rejects_a_payload_of_another_length(#[case] delta: isize) {
    let mut payload = clsig_payload();
    payload.resize(payload.len().saturating_add_signed(delta), 0);
    assert!(matches!(
      P2pMsg::decode_payload(&CommandString::CLSIG, &payload),
      Err(P2pDecodeError::Consensus(_))
    ));
  }

  fn isdlock_payload() -> Vec<u8> {
    let mut payload = vec![0x01, 0x01];
    payload.extend([0x22; 32]);
    payload.extend([0x03, 0x00, 0x00, 0x00]);
    payload.extend([0x33; 32]);
    payload.extend([0x44; 32]);
    payload.extend([0xab; 96]);
    payload
  }

  #[rstest]
  fn isdlock_is_an_instant_send_lock() {
    let item = InstantSendLock {
      version: 1,
      inputs: vec![OutPoint {
        hash: TxHash::from_lendian([0x22; 32]),
        index: 3,
      }],
      txid: TxHash::from_lendian([0x33; 32]),
      cycle_hash: BlockHash::from_lendian([0x44; 32]),
      sig: BlsSigBytes::from_bytes([0xab; 96]),
    };
    let msg = P2pMsg::decode_payload(&CommandString::ISDLOCK, &isdlock_payload());
    assert_eq!(msg, Ok(P2pMsg::IsdLock(item.clone())));
    let mut buf = Vec::new();
    P2pMsg::IsdLock(item).encode_payload(&mut buf);
    assert_eq!(buf, isdlock_payload());
  }

  #[rstest]
  #[case::truncated(-1)]
  #[case::trailing(1)]
  fn isdlock_rejects_a_payload_of_another_length(#[case] delta: isize) {
    let mut payload = isdlock_payload();
    payload.resize(payload.len().saturating_add_signed(delta), 0);
    assert!(matches!(
      P2pMsg::decode_payload(&CommandString::ISDLOCK, &payload),
      Err(P2pDecodeError::Consensus(_))
    ));
  }

  #[rstest]
  #[case::filterclear(CommandString::FILTERCLEAR, P2pMsg::FilterClear)]
  #[case::mempool(CommandString::MEMPOOL, P2pMsg::Mempool)]
  #[case::getsporks(CommandString::GETSPORKS, P2pMsg::GetSporks)]
  #[case::qwatch(CommandString::QWATCH, P2pMsg::QWatch)]
  fn payload_less_messages_are_parsed(#[case] cmd: CommandString, #[case] msg: P2pMsg) {
    assert_eq!(P2pMsg::decode_payload(&cmd, &[]), Ok(msg.clone()));
    assert!(!msg.is_stub());
    assert!(matches!(
      P2pMsg::decode_payload(&cmd, &[0]),
      Err(P2pDecodeError::PayloadNotEmpty { size: 1, .. })
    ));
  }
}
