//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! BIP324 V2 message framing.
//!
//! Handles the 1-byte short-ID dispatch layer that sits between
//! the raw message payload and the BIP324 encrypted transport.

use crate::msg::DashNetworkMessage;
use crate::prelude::*;
use crate::primitives::command::CommandString;
use crate::primitives::short_id::ShortId;
use crate::P2pDecodeError;

/// Encodes a `DashNetworkMessage` into V2 framed bytes.
///
/// The result is ready to pass to `bip324::Payload::genuine()`.
///
/// Format: `[1-byte short_id] [optional 12-byte command] [payload]`
pub fn encode_v2(msg: &DashNetworkMessage, buf: &mut Vec<u8>) {
  match msg.short_id() {
    Some(id) => {
      buf.push(id.0);
    }
    None => {
      // Long format: ID 0 + 12-byte command string.
      buf.push(0);
      let cmd = msg.command();
      buf.extend_from_slice(cmd.as_bytes());
    }
  }
  msg.encode_payload(buf);
}

/// Decodes V2 framed bytes into a `DashNetworkMessage`.
///
/// `payload` is the decrypted content from `bip324::Payload::contents()`.
pub fn decode_v2(payload: &[u8]) -> Result<DashNetworkMessage, P2pDecodeError> {
  if payload.is_empty() {
    return Err(P2pDecodeError::Consensus(String::from(
      "unexpected eof: needed 1 byte, 0 remaining",
    )));
  }

  let short_id = payload[0];
  let rest = &payload[1..];

  if short_id == 0 {
    // Long format: next 12 bytes are the command string.
    if rest.len() < 12 {
      return Err(P2pDecodeError::Consensus(format!(
        "unexpected eof: needed 12 bytes, {} remaining",
        rest.len()
      )));
    }
    let mut cmd_bytes = [0u8; 12];
    cmd_bytes.copy_from_slice(&rest[..12]);
    let cmd = CommandString::from_bytes(cmd_bytes);
    DashNetworkMessage::decode_payload(&cmd, &rest[12..])
  } else {
    // Short ID: resolve to command, then decode payload.
    let sid = ShortId(short_id);
    let cmd = sid
      .to_command()
      .ok_or(P2pDecodeError::UnknownShortId { id: short_id })?;
    DashNetworkMessage::decode_payload(&cmd, rest)
  }
}
