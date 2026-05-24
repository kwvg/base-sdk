//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! User agent string exchanged in version messages.

use crate::encode::{encode_compact_size, BufferDecoder, VecEncoder, WireDecodeError, MAX_P2P_PAYLOAD};
use crate::prelude::*;

use bitcoin_consensus_encoding as encoding;
use dash_primitives::wire;

use core::fmt;

/// Maximum user agent (subversion) length in bytes.
const MAX_USER_AGENT: usize = 256;

/// CompactSize-prefixed user agent bytestring.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct UserAgent(Vec<u8>);

/// The user agent exceeds the 256-byte limit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserAgentTooLong {
  /// Actual length in bytes.
  pub len: usize,
}

impl fmt::Display for UserAgentTooLong {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "user agent too long: {} bytes, max {MAX_USER_AGENT}", self.len)
  }
}

impl UserAgent {
  /// Creates a new user agent from raw bytes.
  ///
  /// # Errors
  ///
  /// Returns `UserAgentTooLong` if `bytes` exceeds 256 bytes.
  pub fn new(bytes: Vec<u8>) -> Result<Self, UserAgentTooLong> {
    if bytes.len() > MAX_USER_AGENT {
      return Err(UserAgentTooLong { len: bytes.len() });
    }
    Ok(Self(bytes))
  }

  /// Returns the user agent bytes as a str, if valid UTF-8.
  pub fn as_str(&self) -> Option<&str> {
    core::str::from_utf8(&self.0).ok()
  }

  /// Returns the raw bytes.
  pub fn as_bytes(&self) -> &[u8] {
    &self.0
  }

  /// Returns the length in bytes.
  pub fn len(&self) -> usize {
    self.0.len()
  }

  /// Returns `true` if the user agent is empty.
  pub fn is_empty(&self) -> bool {
    self.0.is_empty()
  }

  fn decode_from_slice(data: &[u8]) -> Result<Self, WireDecodeError> {
    let sl = &mut &data[..];
    let len = wire::read_compact_size(sl, MAX_USER_AGENT)?;
    let bytes = wire::read_bytes(sl, len)?;
    Ok(Self(bytes.to_vec()))
  }

  fn encode_to_vec(&self) -> Vec<u8> {
    let mut buf = Vec::new();
    encode_compact_size(self.0.len(), &mut buf);
    buf.extend_from_slice(&self.0);
    buf
  }
}

impl fmt::Display for UserAgent {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    match self.as_str() {
      Some(s) => f.write_str(s),
      None => write!(f, "<{} bytes>", self.0.len()),
    }
  }
}

impl encoding::Encodable for UserAgent {
  type Encoder<'e> = VecEncoder;
  fn encoder(&self) -> Self::Encoder<'_> {
    VecEncoder::new(self.encode_to_vec())
  }
}

impl encoding::Decodable for UserAgent {
  type Decoder = BufferDecoder<UserAgent, WireDecodeError>;
  fn decoder() -> Self::Decoder {
    BufferDecoder::new(UserAgent::decode_from_slice, MAX_P2P_PAYLOAD)
  }
}
