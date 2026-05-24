//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Bridge utilities for wrapping cursor-based decode/encode logic behind the
//! `bitcoin_consensus_encoding` ecosystem traits.

use crate::prelude::*;

use bitcoin_consensus_encoding as encoding;

use core::fmt;

/// A decoder that buffers all input and decodes in `end()`.
///
/// Wraps types with complex sequential decode logic (conditional fields,
/// version branching) that cannot be expressed as a composable push-decoder
/// without excessive boilerplate.
pub struct BufferDecoder<T, E> {
  buf: Vec<u8>,
  limit: usize,
  decode_fn: fn(&[u8]) -> Result<T, E>,
}

impl<T, E> fmt::Debug for BufferDecoder<T, E> {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.debug_struct("BufferDecoder")
      .field("buf_len", &self.buf.len())
      .field("limit", &self.limit)
      .finish()
  }
}

impl<T, E> BufferDecoder<T, E> {
  /// Creates a new decoder with the given decode function and
  /// maximum buffer size.
  pub fn new(decode_fn: fn(&[u8]) -> Result<T, E>, limit: usize) -> Self {
    Self {
      buf: Vec::new(),
      limit,
      decode_fn,
    }
  }
}

impl<T, E> encoding::Decoder for BufferDecoder<T, E> {
  type Output = T;
  type Error = E;

  fn push_bytes(&mut self, bytes: &mut &[u8]) -> Result<bool, Self::Error> {
    let remaining = self.limit.saturating_sub(self.buf.len());
    let take = bytes.len().min(remaining);
    self.buf.extend_from_slice(&bytes[..take]);
    *bytes = &bytes[take..];
    Ok(true)
  }

  fn end(self) -> Result<Self::Output, Self::Error> {
    (self.decode_fn)(&self.buf)
  }

  fn read_limit(&self) -> usize {
    self.limit.saturating_sub(self.buf.len())
  }
}

/// An encoder that wraps a pre-built byte vector.
#[derive(Debug)]
pub struct VecEncoder {
  data: Vec<u8>,
  done: bool,
}

impl VecEncoder {
  /// Creates a new encoder wrapping the given bytes.
  pub fn new(data: Vec<u8>) -> Self {
    Self { data, done: false }
  }
}

impl encoding::Encoder for VecEncoder {
  fn current_chunk(&self) -> &[u8] {
    if self.done {
      &[]
    } else {
      &self.data
    }
  }

  fn advance(&mut self) -> bool {
    if self.done {
      false
    } else {
      self.done = true;
      false
    }
  }
}

/// Decode error for cursor-based types exposed through ecosystem traits.
///
/// Wraps `crate::error::DecodeError` so it can be used as a `Decoder::Error`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodeError(crate::error::DecodeError);

impl From<crate::error::DecodeError> for DecodeError {
  fn from(e: crate::error::DecodeError) -> Self {
    Self(e)
  }
}

impl fmt::Display for DecodeError {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "{}", self.0)
  }
}
