//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Consensus encoding support for hash types.

use bitcoin_consensus_encoding as encoding;

use core::fmt;
use core::marker::PhantomData;

/// Generic decoder for N-byte hash types.
#[derive(Clone, Debug)]
pub struct HashDecoder<const N: usize>(encoding::ArrayDecoder<N>);

impl<const N: usize> HashDecoder<N> {
  /// Constructs a new decoder.
  pub const fn new() -> Self {
    Self(encoding::ArrayDecoder::new())
  }
}

impl<const N: usize> Default for HashDecoder<N> {
  fn default() -> Self {
    Self::new()
  }
}

/// Decode error for hash types.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HashDecoderError(pub encoding::UnexpectedEofError);

impl fmt::Display for HashDecoderError {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "hash decode: {}", self.0)
  }
}

impl<const N: usize> encoding::Decoder for HashDecoder<N> {
  type Output = [u8; N];
  type Error = HashDecoderError;

  #[inline]
  fn push_bytes(&mut self, bytes: &mut &[u8]) -> Result<bool, Self::Error> {
    self.0.push_bytes(bytes).map_err(HashDecoderError)
  }

  #[inline]
  fn end(self) -> Result<Self::Output, Self::Error> {
    self.0.end().map_err(HashDecoderError)
  }

  #[inline]
  fn read_limit(&self) -> usize {
    self.0.read_limit()
  }
}

/// Typed decoder that produces a concrete hash type from N raw bytes.
#[derive(Clone, Debug)]
pub struct HashTypeDecoder<T, const N: usize>(HashDecoder<N>, PhantomData<T>);

impl<T, const N: usize> HashTypeDecoder<T, N> {
  /// Constructs a new decoder.
  pub const fn new() -> Self {
    Self(HashDecoder::new(), PhantomData)
  }
}

impl<T, const N: usize> Default for HashTypeDecoder<T, N> {
  fn default() -> Self {
    Self::new()
  }
}

impl<T, const N: usize> encoding::Decoder for HashTypeDecoder<T, N>
where
  T: From<[u8; N]>,
{
  type Output = T;
  type Error = HashDecoderError;

  #[inline]
  fn push_bytes(&mut self, bytes: &mut &[u8]) -> Result<bool, Self::Error> {
    self.0.push_bytes(bytes)
  }

  #[inline]
  fn end(self) -> Result<Self::Output, Self::Error> {
    self.0.end().map(T::from)
  }

  #[inline]
  fn read_limit(&self) -> usize {
    self.0.read_limit()
  }
}
