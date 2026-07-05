//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Variable-length script with CompactSize-prefixed consensus encoding.

use crate::hash_impl;
use crate::prelude::*;

use dash_types::codec::{ArrayBuf, BaseCodec, DecodeError, EncodeBuf};
use dash_types::{impl_type, make_bytes, TypeId};

use core::fmt;

/// A variable-length script, CompactSize-prefixed on the wire.
#[derive(Clone, Eq, Hash, PartialEq, Default, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(transparent))]
pub struct Script(#[cfg_attr(feature = "serde", serde(with = "dash_types::serialize::hex"))] pub Vec<u8>);

impl_type!(Script);

impl BaseCodec for Script {
  fn decode(data: &mut &[u8]) -> Result<Self, DecodeError> {
    Vec::decode(data).map(Self)
  }

  fn encode(&self, buf: &mut impl EncodeBuf) {
    self.0.encode(buf);
  }
}

hash_impl!(Script);

impl Script {
  /// Creates a new script from raw bytes.
  pub fn new(data: Vec<u8>) -> Self {
    Self(data)
  }

  /// Returns a reference to the script bytes.
  pub fn as_bytes(&self) -> &[u8] {
    &self.0
  }

  /// Returns the length in bytes.
  pub fn len(&self) -> usize {
    self.0.len()
  }

  /// Returns whether the script is empty.
  pub fn is_empty(&self) -> bool {
    self.0.is_empty()
  }
}

impl fmt::Debug for Script {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "Script(")?;
    for byte in &self.0 {
      write!(f, "{:02x}", byte)?;
    }
    write!(f, ")")
  }
}

impl fmt::Display for Script {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    for byte in &self.0 {
      write!(f, "{:02x}", byte)?;
    }
    Ok(())
  }
}

make_bytes! {
  /// 20-byte public key hash (RIPEMD-160 of SHA-256).
  KeyId, 20
}

hash_impl!(KeyId);

impl KeyId {
  /// Encode as a Base58Check string with the given version prefix.
  pub fn to_base58c(&self, prefix: u8) -> String {
    let mut buf = ArrayBuf::<21>::new();
    buf.push(prefix);
    self.encode(&mut buf);
    base58ck::encode_check(&buf.into_array())
  }
}
