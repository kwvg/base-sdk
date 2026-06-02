//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! V2 short ID mapping for BIP324 message framing.

use crate::primitives::command::CommandString;

// Maps between V2 1-byte short IDs and command strings.
//
// Bitcoin occupies IDs 0-32 (lower half), Dash occupies 128-168
// (upper half). ID 0 means "long format" -- a 12-byte command
// string follows instead.

/// Total number of Bitcoin short IDs (including slot 0 = long format).
const BITCOIN_COUNT: usize = 33;
/// Offset where Dash short IDs begin.
const DASH_OFFSET: u8 = 128;
/// Number of Dash short IDs.
const DASH_COUNT: usize = 41;

/// Bitcoin short ID table (index = short ID byte).
///
/// Slot 0 is the long-format sentinel (empty string).
/// Empty strings in other slots are intentionally unassigned.
static BITCOIN_IDS: [&str; BITCOIN_COUNT] = [
  "",             // 0: long format
  "addr",         // 1
  "block",        // 2
  "blocktxn",     // 3
  "cmpctblock",   // 4
  "",             // 5: feefilter (unused in Dash)
  "filteradd",    // 6
  "filterclear",  // 7
  "filterload",   // 8
  "getblocks",    // 9
  "getblocktxn",  // 10
  "getdata",      // 11
  "getheaders",   // 12
  "headers",      // 13
  "inv",          // 14
  "mempool",      // 15
  "merkleblock",  // 16
  "notfound",     // 17
  "ping",         // 18
  "pong",         // 19
  "sendcmpct",    // 20
  "tx",           // 21
  "getcfilters",  // 22
  "cfilter",      // 23
  "getcfheaders", // 24
  "cfheaders",    // 25
  "getcfcheckpt", // 26
  "cfcheckpt",    // 27
  "addrv2",       // 28
  "",             // 29
  "",             // 30
  "",             // 31
  "",             // 32
];

/// Dash short ID table (index 0 = short ID 128).
static DASH_IDS: [&str; DASH_COUNT] = [
  "spork",        // 128
  "getsporks",    // 129
  "senddsq",      // 130
  "dsa",          // 131
  "dsi",          // 132
  "dsf",          // 133
  "dss",          // 134
  "dsc",          // 135
  "dssu",         // 136
  "dstx",         // 137
  "dsq",          // 138
  "ssc",          // 139
  "govsync",      // 140
  "govobj",       // 141
  "govobjvote",   // 142
  "getmnlistd",   // 143
  "mnlistdiff",   // 144
  "qsendrecsigs", // 145
  "qfcommit",     // 146
  "qcontrib",     // 147
  "qcomplaint",   // 148
  "qjustify",     // 149
  "qpcommit",     // 150
  "qwatch",       // 151
  "qsigsesann",   // 152
  "qsigsinv",     // 153
  "qgetsigs",     // 154
  "qbsigs",       // 155
  "qsigrec",      // 156
  "qsigshare",    // 157
  "qgetdata",     // 158
  "qdata",        // 159
  "clsig",        // 160
  "isdlock",      // 161
  "mnauth",       // 162
  "getheaders2",  // 163
  "sendheaders2", // 164
  "headers2",     // 165
  "getqrinfo",    // 166
  "qrinfo",       // 167
  "platformban",  // 168
];

/// A resolved V2 short ID.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ShortId(pub u8);

impl ShortId {
  /// Long-format sentinel (a 12-byte command follows).
  pub const LONG_FORMAT: Self = Self(0);

  /// Returns `true` if this ID is valid (maps to a non-empty command).
  pub fn is_valid(self) -> bool {
    self.to_command_str().is_some()
  }

  /// Resolves the short ID to its command name, if known.
  pub fn to_command_str(self) -> Option<&'static str> {
    let id = self.0;
    if (id as usize) < BITCOIN_COUNT {
      let s = BITCOIN_IDS[id as usize];
      if s.is_empty() {
        None
      } else {
        Some(s)
      }
    } else if id >= DASH_OFFSET {
      let idx = (id - DASH_OFFSET) as usize;
      if idx < DASH_COUNT {
        let s = DASH_IDS[idx];
        if s.is_empty() {
          None
        } else {
          Some(s)
        }
      } else {
        None
      }
    } else {
      None
    }
  }

  /// Resolves the short ID to a `CommandString`, if known.
  pub fn to_command(self) -> Option<CommandString> {
    self.to_command_str().map(CommandString::from_static)
  }

  /// Looks up the short ID for a given command string.
  ///
  /// Returns `None` if the command has no short ID (must use
  /// long format with ID 0).
  pub fn from_command(cmd: &CommandString) -> Option<Self> {
    let s = cmd.as_str();
    // Search Bitcoin table (skip slot 0 which is the sentinel).
    for (i, &entry) in BITCOIN_IDS.iter().enumerate().skip(1) {
      if entry == s {
        return Some(Self(i as u8));
      }
    }
    // Search Dash table.
    for (i, &entry) in DASH_IDS.iter().enumerate() {
      if entry == s {
        return Some(Self(DASH_OFFSET + i as u8));
      }
    }
    None
  }

  /// Returns `true` if the byte is in a range that could hold a
  /// valid short ID (Bitcoin 1-32 or Dash 128-168).
  pub fn is_valid_range(id: u8) -> bool {
    (1..BITCOIN_COUNT as u8).contains(&id) || (id >= DASH_OFFSET && (id - DASH_OFFSET) < DASH_COUNT as u8)
  }
}
