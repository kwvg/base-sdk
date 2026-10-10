//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! BIP324 V2 message framing.

use crate::command::CommandString;
use crate::msg::P2pMsg;
use crate::prelude::*;
use crate::short_id::ShortId;
use crate::{P2pDecodeError, ProtocolVersion};

/// Encodes a `P2pMsg` into V2 framed bytes for a peer at
/// [`ProtocolVersion::CURRENT`].
pub fn encode_v2(msg: &P2pMsg, buf: &mut Vec<u8>) {
  encode_v2_with_version(msg, buf, ProtocolVersion::CURRENT);
}

/// Encodes a `P2pMsg` into V2 framed bytes for a peer at `version`, the
/// version negotiated with the peer.
pub fn encode_v2_with_version(msg: &P2pMsg, buf: &mut Vec<u8>, version: ProtocolVersion) {
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
  msg.encode_payload_with_version(buf, version);
}

/// Decodes V2 framed bytes into a `P2pMsg` sent at
/// [`ProtocolVersion::CURRENT`].
///
/// # Errors
///
/// Returns [`P2pDecodeError`] on an unknown command or short ID, or a
/// malformed payload.
pub fn decode_v2(payload: &[u8]) -> Result<P2pMsg, P2pDecodeError> {
  decode_v2_with_version(payload, ProtocolVersion::CURRENT)
}

/// Decodes V2 framed bytes into a `P2pMsg` sent at `version`, the version
/// negotiated with the peer.
///
/// # Errors
///
/// Returns [`P2pDecodeError`] on an unknown command or short ID, or a
/// malformed payload.
pub fn decode_v2_with_version(payload: &[u8], version: ProtocolVersion) -> Result<P2pMsg, P2pDecodeError> {
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
    P2pMsg::decode_payload_with_version(&cmd, &rest[12..], version)
  } else {
    // Short ID: resolve to command, then decode payload.
    let sid = ShortId(short_id);
    let cmd = sid
      .to_command()
      .ok_or(P2pDecodeError::UnknownShortId { id: short_id })?;
    P2pMsg::decode_payload_with_version(&cmd, rest, version)
  }
}

#[cfg(test)]
mod tests {
  use super::{decode_v2, decode_v2_with_version, encode_v2, encode_v2_with_version};
  use crate::prelude::*;
  use crate::{P2pMsg, Ping, ProtocolVersion};

  use rstest::rstest;

  #[rstest]
  fn version_free_forms_use_the_current_version() {
    let msg = P2pMsg::Ping(Ping { nonce: 7 });
    let (mut plain, mut versioned) = (Vec::new(), Vec::new());
    encode_v2(&msg, &mut plain);
    encode_v2_with_version(&msg, &mut versioned, ProtocolVersion::CURRENT);
    assert_eq!(plain, versioned);
    assert_eq!(
      decode_v2(&plain),
      decode_v2_with_version(&plain, ProtocolVersion::CURRENT)
    );
  }

  #[rstest]
  #[case::baseline(ProtocolVersion::BIP324_BASELINE)]
  #[case::current(ProtocolVersion::CURRENT)]
  fn round_trips_at_the_peer_version(#[case] version: ProtocolVersion) {
    let msg = P2pMsg::Ping(Ping { nonce: 7 });
    let mut buf = Vec::new();
    encode_v2_with_version(&msg, &mut buf, version);
    assert_eq!(decode_v2_with_version(&buf, version), Ok(msg));
  }
}
