//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Bridge utilities for `Codec` types to `bitcoin_consensus_encoding` traits.

use crate::prelude::*;

use bitcoin_consensus_encoding as encoding;

use core::fmt;

/// Maximum serialized object size (32 MiB).
pub const MAX_SER_SIZE: usize = 0x0200_0000;

/// A decoder that buffers all input and decodes in `end()`.
///
/// Wraps types with complex sequential decode logic (conditional fields,
/// version branching) that cannot be expressed as a composable push-decoder
/// without excessive boilerplate.
pub struct BufferDecoder<T, E> {
  buf: Vec<u8>,
  limit: usize,
  decode_fn: fn(&mut &[u8]) -> Result<T, E>,
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
  pub const fn new(decode_fn: fn(&mut &[u8]) -> Result<T, E>, limit: usize) -> Self {
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
    (self.decode_fn)(&mut &self.buf[..])
  }

  fn read_limit(&self) -> usize {
    self.limit.saturating_sub(self.buf.len())
  }
}

/// An encoder that wraps a pre-built byte vector.
#[derive(Debug, Clone, PartialEq, Eq)]
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

/// Generates `Encodable` + `Decodable` for a `Codec` implementor.
#[macro_export]
macro_rules! impl_type {
  ($ty:ty) => {
    $crate::impl_type!($ty, $crate::MAX_SER_SIZE);
  };
  ($ty:ty, $max:expr) => {
    impl ::bitcoin_consensus_encoding::Encodable for $ty {
      type Encoder<'e> = $crate::VecEncoder;
      fn encoder(&self) -> Self::Encoder<'_> {
        let mut buf = ::alloc::vec::Vec::new();
        $crate::codec::Codec::encode(self, &mut buf);
        $crate::VecEncoder::new(buf)
      }
    }

    impl ::bitcoin_consensus_encoding::Decodable for $ty {
      type Decoder = $crate::BufferDecoder<$ty, $crate::codec::DecodeError>;
      fn decoder() -> Self::Decoder {
        $crate::BufferDecoder::new(<$ty as $crate::codec::Codec>::decode, $max)
      }
    }
  };
}
