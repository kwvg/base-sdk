//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Twelve-byte null-padded command string for P2P message dispatch.

use bitcoin_consensus_encoding as encoding;

use core::fmt;

/// A 12-byte, null-padded ASCII command identifying a P2P message type.
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct CommandString([u8; 12]);

impl CommandString {
  /// Builds a command string from a static `&str` at compile time.
  ///
  /// # Panics
  ///
  /// Compile-time panic if `s` is longer than 12 bytes.
  pub const fn from_static(s: &str) -> Self {
    let b = s.as_bytes();
    let len = b.len();
    assert!(len <= 12, "command string exceeds 12 bytes");
    let mut buf = [0u8; 12];
    let mut i = 0;
    while i < len {
      buf[i] = b[i];
      i += 1;
    }
    Self(buf)
  }

  /// Wraps raw bytes into a command string.
  pub const fn from_bytes(bytes: [u8; 12]) -> Self {
    Self(bytes)
  }

  /// Returns the raw 12-byte command buffer.
  pub const fn as_bytes(&self) -> &[u8; 12] {
    &self.0
  }

  /// Returns the command as a `&str` (trimmed of null padding).
  pub fn as_str(&self) -> &str {
    let end = self.0.iter().position(|&b| b == 0).unwrap_or(12);
    // The bytes are always valid ASCII written by from_static or
    // validated on decode, so this conversion is sound.
    core::str::from_utf8(&self.0[..end]).unwrap_or("")
  }

  /// Peer address list (v1).
  pub const ADDR: Self = Self::from_static("addr");
  /// Peer address list (v2, BIP155).
  pub const ADDRV2: Self = Self::from_static("addrv2");
  /// Request peer addresses.
  pub const GETADDR: Self = Self::from_static("getaddr");
  /// Signal addrv2 support.
  pub const SENDADDRV2: Self = Self::from_static("sendaddrv2");
  /// Inventory announcement.
  pub const INV: Self = Self::from_static("inv");
  /// Request specific inventory.
  pub const GETDATA: Self = Self::from_static("getdata");
  /// Requested inventory not found.
  pub const NOTFOUND: Self = Self::from_static("notfound");
  /// Block headers request.
  pub const GETHEADERS: Self = Self::from_static("getheaders");
  /// Block headers.
  pub const HEADERS: Self = Self::from_static("headers");
  /// Keepalive request.
  pub const PING: Self = Self::from_static("ping");
  /// Keepalive response.
  pub const PONG: Self = Self::from_static("pong");
  /// BIP157: request compact filters.
  pub const GETCFILTERS: Self = Self::from_static("getcfilters");
  /// BIP157: compact filter.
  pub const CFILTER: Self = Self::from_static("cfilter");
  /// BIP157: request compact filter headers.
  pub const GETCFHEADERS: Self = Self::from_static("getcfheaders");
  /// BIP157: compact filter headers.
  pub const CFHEADERS: Self = Self::from_static("cfheaders");
  /// BIP157: request compact filter checkpoints.
  pub const GETCFCHECKPT: Self = Self::from_static("getcfcheckpt");
  /// BIP157: compact filter checkpoints.
  pub const CFCHECKPT: Self = Self::from_static("cfcheckpt");
  /// Block data.
  pub const BLOCK: Self = Self::from_static("block");
  /// BIP152: compact block transactions.
  pub const BLOCKTXN: Self = Self::from_static("blocktxn");
  /// BIP152: compact block.
  pub const CMPCTBLOCK: Self = Self::from_static("cmpctblock");
  /// BIP37: add data to bloom filter.
  pub const FILTERADD: Self = Self::from_static("filteradd");
  /// BIP37: clear bloom filter.
  pub const FILTERCLEAR: Self = Self::from_static("filterclear");
  /// BIP37: load bloom filter.
  pub const FILTERLOAD: Self = Self::from_static("filterload");
  /// Request block hashes.
  pub const GETBLOCKS: Self = Self::from_static("getblocks");
  /// BIP152: request compact block transactions.
  pub const GETBLOCKTXN: Self = Self::from_static("getblocktxn");
  /// Request mempool contents.
  pub const MEMPOOL: Self = Self::from_static("mempool");
  /// BIP37: filtered block.
  pub const MERKLEBLOCK: Self = Self::from_static("merkleblock");
  /// BIP152: signal compact block support.
  pub const SENDCMPCT: Self = Self::from_static("sendcmpct");
  /// Transaction.
  pub const TX: Self = Self::from_static("tx");

  /// Protocol handshake.
  pub const VERSION: Self = Self::from_static("version");
  /// Handshake acknowledgement.
  pub const VERACK: Self = Self::from_static("verack");
  /// Prefer unsolicited headers announcements.
  pub const SENDHEADERS: Self = Self::from_static("sendheaders");
  /// BIP330: transaction reconciliation.
  pub const SENDTXRCNCL: Self = Self::from_static("sendtxrcncl");

  /// Spork broadcast/request.
  pub const SPORK: Self = Self::from_static("spork");
  /// Request active sporks.
  pub const GETSPORKS: Self = Self::from_static("getsporks");
  /// Signal CoinJoin queue relay.
  pub const SENDDSQ: Self = Self::from_static("senddsq");
  /// CoinJoin: accept denomination.
  pub const DSA: Self = Self::from_static("dsa");
  /// CoinJoin: submit inputs.
  pub const DSI: Self = Self::from_static("dsi");
  /// CoinJoin: final transaction.
  pub const DSF: Self = Self::from_static("dsf");
  /// CoinJoin: sign final transaction.
  pub const DSS: Self = Self::from_static("dss");
  /// CoinJoin: complete.
  pub const DSC: Self = Self::from_static("dsc");
  /// CoinJoin: status update.
  pub const DSSU: Self = Self::from_static("dssu");
  /// CoinJoin: broadcast transaction.
  pub const DSTX: Self = Self::from_static("dstx");
  /// CoinJoin: queue entry.
  pub const DSQ: Self = Self::from_static("dsq");
  /// Sync status count.
  pub const SSC: Self = Self::from_static("ssc");
  /// Governance sync request.
  pub const GOVSYNC: Self = Self::from_static("govsync");
  /// Governance object.
  pub const GOVOBJ: Self = Self::from_static("govobj");
  /// Governance object vote.
  pub const GOVOBJVOTE: Self = Self::from_static("govobjvote");
  /// Request masternode list diff.
  pub const GETMNLISTD: Self = Self::from_static("getmnlistd");
  /// Masternode list diff.
  pub const MNLISTDIFF: Self = Self::from_static("mnlistdiff");
  /// LLMQ: send recovered signatures.
  pub const QSENDRECSIGS: Self = Self::from_static("qsendrecsigs");
  /// LLMQ: final commitment.
  pub const QFCOMMIT: Self = Self::from_static("qfcommit");
  /// LLMQ: contribution.
  pub const QCONTRIB: Self = Self::from_static("qcontrib");
  /// LLMQ: complaint.
  pub const QCOMPLAINT: Self = Self::from_static("qcomplaint");
  /// LLMQ: justification.
  pub const QJUSTIFY: Self = Self::from_static("qjustify");
  /// LLMQ: premature commitment.
  pub const QPCOMMIT: Self = Self::from_static("qpcommit");
  /// LLMQ: watch quorums.
  pub const QWATCH: Self = Self::from_static("qwatch");
  /// LLMQ: signing session announcement.
  pub const QSIGSESANN: Self = Self::from_static("qsigsesann");
  /// LLMQ: signature shares inventory.
  pub const QSIGSINV: Self = Self::from_static("qsigsinv");
  /// LLMQ: request signature shares.
  pub const QGETSIGS: Self = Self::from_static("qgetsigs");
  /// LLMQ: batched signature shares.
  pub const QBSIGS: Self = Self::from_static("qbsigs");
  /// LLMQ: recovered signature.
  pub const QSIGREC: Self = Self::from_static("qsigrec");
  /// LLMQ: single signature share.
  pub const QSIGSHARE: Self = Self::from_static("qsigshare");
  /// LLMQ: request quorum data.
  pub const QGETDATA: Self = Self::from_static("qgetdata");
  /// LLMQ: quorum data.
  pub const QDATA: Self = Self::from_static("qdata");
  /// ChainLock signature.
  pub const CLSIG: Self = Self::from_static("clsig");
  /// InstantSend deterministic lock.
  pub const ISDLOCK: Self = Self::from_static("isdlock");
  /// Masternode authentication.
  pub const MNAUTH: Self = Self::from_static("mnauth");
  /// Compressed headers request.
  pub const GETHEADERS2: Self = Self::from_static("getheaders2");
  /// Prefer compressed header announcements.
  pub const SENDHEADERS2: Self = Self::from_static("sendheaders2");
  /// Compressed headers.
  pub const HEADERS2: Self = Self::from_static("headers2");
  /// Request quorum rotation info.
  pub const GETQRINFO: Self = Self::from_static("getqrinfo");
  /// Quorum rotation info.
  pub const QRINFO: Self = Self::from_static("qrinfo");
  /// DIP-0031: platform ban.
  pub const PLATFORMBAN: Self = Self::from_static("platformban");
}

impl fmt::Debug for CommandString {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "CommandString(\"{}\")", self.as_str())
  }
}

impl fmt::Display for CommandString {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.write_str(self.as_str())
  }
}

encoding::encoder_newtype_exact! {
  /// Encoder for [`CommandString`].
  pub struct CommandStringEncoder<'e>(encoding::ArrayEncoder<12>);
}

impl encoding::Encodable for CommandString {
  type Encoder<'e> = CommandStringEncoder<'e>;
  fn encoder(&self) -> Self::Encoder<'_> {
    CommandStringEncoder::new(encoding::ArrayEncoder::without_length_prefix(*self.as_bytes()))
  }
}

/// Decoder for [`CommandString`].
#[derive(Clone, Debug)]
pub struct CommandStringDecoder(encoding::ArrayDecoder<12>);

impl CommandStringDecoder {
  /// Creates a new decoder.
  pub const fn new() -> Self {
    Self(encoding::ArrayDecoder::new())
  }
}

impl Default for CommandStringDecoder {
  fn default() -> Self {
    Self::new()
  }
}

/// Decode error for [`CommandString`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandStringDecoderError(encoding::UnexpectedEofError);

impl fmt::Display for CommandStringDecoderError {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "command string decode: {}", self.0)
  }
}

impl encoding::Decoder for CommandStringDecoder {
  type Output = CommandString;
  type Error = CommandStringDecoderError;

  fn push_bytes(&mut self, bytes: &mut &[u8]) -> Result<bool, Self::Error> {
    self.0.push_bytes(bytes).map_err(CommandStringDecoderError)
  }

  fn end(self) -> Result<Self::Output, Self::Error> {
    let buf = self.0.end().map_err(CommandStringDecoderError)?;
    Ok(CommandString::from_bytes(buf))
  }

  fn read_limit(&self) -> usize {
    self.0.read_limit()
  }
}

impl encoding::Decodable for CommandString {
  type Decoder = CommandStringDecoder;
  fn decoder() -> Self::Decoder {
    CommandStringDecoder::new()
  }
}
