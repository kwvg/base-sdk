//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! P2P message types and dispatch.

use crate::prelude::*;
use crate::primitives::command::CommandString;
use crate::primitives::short_id::ShortId;

use bitcoin_consensus_encoding as encoding;

pub mod addr;
pub mod cfcheckpt;
pub mod cfheaders;
pub mod cfilter;
pub mod govobj;
pub mod govobjvote;
pub mod govsync;
pub mod headers;
pub mod headers2;
pub mod inv;
pub mod mnlistdiff;
pub mod ping;
pub mod version;

pub use addr::{Addr, AddrV2Msg};
pub use cfcheckpt::{CFCheckpt, GetCFCheckpt};
pub use cfheaders::{CFHeaders, GetCFHeaders};
pub use cfilter::{CFilter, GetCFilters};
pub use govobj::GovObj;
pub use govobjvote::GovObjVote;
pub use govsync::GovSync;
pub use headers::{GetHeaders, Headers};
pub use headers2::{GetHeaders2, Headers2};
pub use inv::{GetData, Inv, NotFound};
pub use mnlistdiff::{GetMnListDiff, MnListDiff};
pub use ping::{Ping, Pong};
pub use version::Version;

/// Decode helper: decode from slice, mapping the error.
fn decode_msg<T: encoding::Decodable>(payload: &[u8]) -> Result<T, crate::P2pDecodeError>
where
  <T::Decoder as encoding::Decoder>::Error: core::fmt::Display,
{
  encoding::decode_from_slice(payload).map_err(|e| crate::P2pDecodeError::Consensus(format!("{e}")))
}

/// Generates `DashNetworkMessage`, its `command()`, `short_id()`,
/// `is_stub()`, `decode_payload()`, and `encode_payload()` methods
/// from a single definition table. Each entry is written once; the
/// macro fans it out to every match arm and enum variant.
macro_rules! define_network_messages {
  (
    // Fully-parsed messages with a typed payload.
    parsed {
      $(
        $(#[$p_doc:meta])*
        $p_variant:ident ( $p_type:ty ) => $p_cmd:ident
      ),* $(,)?
    }
    // Fully-parsed messages with an empty payload.
    parsed_empty {
      $(
        $(#[$pe_doc:meta])*
        $pe_variant:ident => $pe_cmd:ident
      ),* $(,)?
    }
    // Recognised but not-yet-implemented (raw `Vec<u8>` payload).
    stub {
      $(
        $(#[$s_doc:meta])*
        $s_variant:ident => $s_cmd:ident
      ),* $(,)?
    }
    // Recognised but not-yet-implemented (empty payload).
    stub_empty {
      $(
        $(#[$se_doc:meta])*
        $se_variant:ident => $se_cmd:ident
      ),* $(,)?
    }
  ) => {
    /// A Dash P2P network message.
    ///
    /// Fully-parsed variants carry typed payloads. Recognised but
    /// not-yet-implemented messages use `Vec<u8>` to hold the raw
    /// payload so callers can identify *what* was received (for
    /// logging) without needing a full decoder.
    #[derive(Clone, Debug, Eq, Hash, PartialEq)]
    pub enum DashNetworkMessage {
      $( $(#[$p_doc])* $p_variant($p_type), )*
      $( $(#[$pe_doc])* $pe_variant, )*
      $( $(#[$s_doc])* $s_variant(Vec<u8>), )*
      $( $(#[$se_doc])* $se_variant, )*
    }

    impl DashNetworkMessage {
      /// Returns the 12-byte command string for this message.
      pub fn command(&self) -> CommandString {
        match self {
          $( Self::$p_variant(_) => CommandString::$p_cmd, )*
          $( Self::$pe_variant => CommandString::$pe_cmd, )*
          $( Self::$s_variant(_) => CommandString::$s_cmd, )*
          $( Self::$se_variant => CommandString::$se_cmd, )*
        }
      }

      /// Returns the V2 short ID for this message, if one exists.
      pub fn short_id(&self) -> Option<ShortId> {
        ShortId::from_command(&self.command())
      }

      /// Returns `true` when the message type is recognised but
      /// its payload is not fully decoded (a stub).
      pub fn is_stub(&self) -> bool {
        match self {
          $( Self::$p_variant(_) => false, )*
          $( Self::$pe_variant => false, )*
          $( Self::$s_variant(_) => true, )*
          $( Self::$se_variant => true, )*
        }
      }

      /// Decodes a message from its command string and raw payload.
      ///
      /// Fully-implemented messages are decoded into typed variants.
      /// Recognised stubs retain the raw payload as `Vec<u8>`.
      pub fn decode_payload(
        cmd: &CommandString,
        payload: &[u8],
      ) -> Result<Self, crate::P2pDecodeError> {
        let raw = || Vec::from(payload);
        let msg = match *cmd {
          $( CommandString::$p_cmd => Self::$p_variant(decode_msg(payload)?), )*
          $( CommandString::$pe_cmd => Self::$pe_variant, )*
          $( CommandString::$s_cmd => Self::$s_variant(raw()), )*
          $( CommandString::$se_cmd => Self::$se_variant, )*
          _ => return Err(crate::P2pDecodeError::UnknownCommand { bytes: *cmd.as_bytes() }),
        };
        Ok(msg)
      }

      /// Encodes this message's payload (without command/short-ID
      /// framing).
      pub fn encode_payload(&self, buf: &mut Vec<u8>) {
        match self {
          $(
            Self::$p_variant(m) => {
              buf.extend_from_slice(&encoding::encode_to_vec(m));
            }
          )*
          $( Self::$pe_variant => {} )*
          $( Self::$s_variant(raw) => buf.extend_from_slice(raw), )*
          $( Self::$se_variant => {} )*
        }
      }
    }
  };
}

define_network_messages! {
  parsed {
    /// Protocol version exchange.
    Version(Version) => VERSION,
    /// Keepalive request.
    Ping(Ping) => PING,
    /// Keepalive response.
    Pong(Pong) => PONG,
    /// V1 address list.
    Addr(Addr) => ADDR,
    /// BIP155 V2 address list.
    AddrV2(AddrV2Msg) => ADDRV2,
    /// Inventory announcement.
    Inv(Inv) => INV,
    /// Request specific inventory.
    GetData(GetData) => GETDATA,
    /// Inventory not found.
    NotFound(NotFound) => NOTFOUND,
    /// Request block headers.
    GetHeaders(GetHeaders) => GETHEADERS,
    /// Block headers.
    Headers(Headers) => HEADERS,
    /// Request compressed block headers.
    GetHeaders2(GetHeaders2) => GETHEADERS2,
    /// Compressed block headers.
    Headers2(Headers2) => HEADERS2,
    /// Request compact filters.
    GetCFilters(GetCFilters) => GETCFILTERS,
    /// Compact block filter.
    CFilter(CFilter) => CFILTER,
    /// Request compact filter headers.
    GetCFHeaders(GetCFHeaders) => GETCFHEADERS,
    /// Compact filter headers.
    CFHeaders(CFHeaders) => CFHEADERS,
    /// Request compact filter checkpoints.
    GetCFCheckpt(GetCFCheckpt) => GETCFCHECKPT,
    /// Compact filter checkpoints.
    CFCheckpt(CFCheckpt) => CFCHECKPT,
    /// Governance sync request.
    GovSync(GovSync) => GOVSYNC,
    /// Governance object.
    GovObj(GovObj) => GOVOBJ,
    /// Governance vote.
    GovObjVote(GovObjVote) => GOVOBJVOTE,
    /// Request MN list diff.
    GetMnListDiff(GetMnListDiff) => GETMNLISTD,
    /// MN list diff.
    MnListDiff(MnListDiff) => MNLISTDIFF,
  }

  parsed_empty {
    /// Version acknowledgement.
    Verack => VERACK,
    /// Request peer addresses.
    GetAddr => GETADDR,
    /// Signal addrv2 support.
    SendAddrV2 => SENDADDRV2,
    /// Prefer unsolicited header announcements.
    SendHeaders => SENDHEADERS,
    /// Prefer compressed header announcements.
    SendHeaders2 => SENDHEADERS2,
  }

  stub {
    // Bitcoin base protocol
    /// Block data.
    Block => BLOCK,
    /// BIP152: compact block transactions.
    BlockTxn => BLOCKTXN,
    /// BIP152: compact block.
    CmpctBlock => CMPCTBLOCK,
    /// BIP37: add data to bloom filter.
    FilterAdd => FILTERADD,
    /// BIP37: load bloom filter.
    FilterLoad => FILTERLOAD,
    /// Request block hashes.
    GetBlocks => GETBLOCKS,
    /// BIP152: request compact block transactions.
    GetBlockTxn => GETBLOCKTXN,
    /// BIP37: filtered block.
    MerkleBlock => MERKLEBLOCK,
    /// BIP152: signal compact block support.
    SendCmpct => SENDCMPCT,
    /// Transaction.
    Tx => TX,
    /// BIP330: transaction reconciliation.
    SendTxRcncl => SENDTXRCNCL,
    // Sporks
    /// Spork broadcast/request.
    Spork => SPORK,
    // CoinJoin
    /// CoinJoin: accept denomination.
    Dsa => DSA,
    /// CoinJoin: submit inputs.
    Dsi => DSI,
    /// CoinJoin: final transaction.
    Dsf => DSF,
    /// CoinJoin: sign final transaction.
    Dss => DSS,
    /// CoinJoin: complete.
    Dsc => DSC,
    /// CoinJoin: status update.
    Dssu => DSSU,
    /// CoinJoin: broadcast transaction.
    Dstx => DSTX,
    /// CoinJoin: queue entry.
    Dsq => DSQ,
    /// Sync status count.
    Ssc => SSC,
    // LLMQ / Quorum
    /// LLMQ: final commitment.
    QfCommit => QFCOMMIT,
    /// LLMQ: contribution.
    QContrib => QCONTRIB,
    /// LLMQ: complaint.
    QComplaint => QCOMPLAINT,
    /// LLMQ: justification.
    QJustify => QJUSTIFY,
    /// LLMQ: premature commitment.
    QpCommit => QPCOMMIT,
    /// LLMQ: signing session announcement.
    QSigSesAnn => QSIGSESANN,
    /// LLMQ: signature shares inventory.
    QSigsInv => QSIGSINV,
    /// LLMQ: request signature shares.
    QGetSigs => QGETSIGS,
    /// LLMQ: batched signature shares.
    QbSigs => QBSIGS,
    /// LLMQ: recovered signature.
    QSigRec => QSIGREC,
    /// LLMQ: single signature share.
    QSigShare => QSIGSHARE,
    /// LLMQ: request quorum data.
    QGetData => QGETDATA,
    /// LLMQ: quorum data.
    QData => QDATA,
    // InstantSend / ChainLock
    /// ChainLock signature.
    ClSig => CLSIG,
    /// InstantSend deterministic lock.
    IsdLock => ISDLOCK,
    // Masternode auth / rotation
    /// Masternode authentication.
    MnAuth => MNAUTH,
    /// Request quorum rotation info.
    GetQrInfo => GETQRINFO,
    /// Quorum rotation info.
    QrInfo => QRINFO,
    // Platform
    /// DIP-0031: platform ban.
    PlatformBan => PLATFORMBAN,
  }

  stub_empty {
    /// BIP37: clear bloom filter.
    FilterClear => FILTERCLEAR,
    /// Request mempool contents.
    Mempool => MEMPOOL,
    /// Request active sporks.
    GetSporks => GETSPORKS,
    /// Signal CoinJoin queue relay.
    SendDsq => SENDDSQ,
    /// LLMQ: send recovered signatures.
    QSendRecSigs => QSENDRECSIGS,
    /// LLMQ: watch quorums.
    QWatch => QWATCH,
  }
}
