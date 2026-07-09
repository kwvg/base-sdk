//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! secp256k1 public key byte bag.

use crate::prelude::*;

use bitcoin_hashes::{ripemd160, sha256};
use cfg_if::cfg_if;
use dash_num::Hash160;
use dash_types::codec::{
  read_bytes, read_compact_size, write_compact_size, BaseCodec, DecodeError, EncodeBuf, Hashable,
};
use dash_types::TypeId;
use dash_types::{enum_map, impl_type};

use core::cmp::Ordering;
use core::fmt::{Debug, Display, Formatter, Result as FmtResult};

/// Raw secp256k1 public key length without hints.
pub const ECDSA_PK_LEN: usize = 64;

// secp256k1 compressed public key length with compression bit.
const ECDSA_PKCMP_LEN: usize = (ECDSA_PK_LEN / 2) + 1;

enum_map! {
  /// SEC1 public key header byte.
  #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
  #[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
  pub(super) enum Sec1Byte, u8 {
    /// Compressed, even Y coordinate.
    CompEven = 0x02,
    /// Compressed, odd Y coordinate.
    CompOdd = 0x03,
    /// Uncompressed, no parity hint.
    Uncomp = 0x04,
    /// Uncompressed, even Y hint (non-standard).
    UncompEven = 0x06,
    /// Uncompressed, odd Y hint (non-standard).
    UncompOdd = 0x07,
  }
}

impl Sec1Byte {
  /// Whether this prefix indicates a compressed key.
  pub const fn is_compressed(self) -> bool {
    matches!(self, Self::CompEven | Self::CompOdd)
  }

  /// Header-inclusive expected key length.
  pub const fn size(self) -> usize {
    match self {
      Self::CompEven | Self::CompOdd => ECDSA_PKCMP_LEN,
      Self::Uncomp | Self::UncompEven | Self::UncompOdd => ECDSA_PK_LEN + 1,
    }
  }
}

/// SEC-1 encoded ECDSA public key bytes.
#[derive(Clone, Copy, Eq, Hash, PartialEq, TypeId)]
pub struct EcdsaPkBytes([u8; ECDSA_PK_LEN + 1]);

impl EcdsaPkBytes {
  /// Copies raw bytes without validation.
  pub(super) fn from_raw(bytes: &[u8]) -> Self {
    let mut buf = [0xFFu8; ECDSA_PK_LEN + 1];
    let len = bytes.len().min(buf.len());
    buf[..len].copy_from_slice(&bytes[..len]);
    Self(buf)
  }

  /// SEC1 header prefix, or `None` if the buffer is invalid.
  pub(super) fn prefix(&self) -> Option<Sec1Byte> {
    Sec1Byte::from_base(self.0[0])
  }

  /// The raw SEC1 bytes.
  pub fn as_bytes(&self) -> &[u8] {
    &self.0[..self.size()]
  }

  /// Returns `true` when the key is compressed.
  pub fn is_compressed(&self) -> bool {
    self.prefix().is_some_and(|p| p.is_compressed())
  }

  /// Returns `true` when the key has a valid header byte.
  pub fn is_valid(&self) -> bool {
    self.prefix().is_some()
  }

  /// Constructs from raw SEC1 bytes.
  pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
    let prefix = Sec1Byte::from_base(*bytes.first()?)?;
    if bytes.len() != prefix.size() {
      return None;
    }
    Some(Self::from_raw(bytes))
  }

  /// Active byte length, or 0 if invalid.
  pub fn size(&self) -> usize {
    match self.prefix() {
      Some(p) => p.size(),
      None => 0,
    }
  }
}

impl BaseCodec for EcdsaPkBytes {
  fn decode(data: &mut &[u8]) -> Result<Self, DecodeError> {
    let n = read_compact_size(data, ECDSA_PK_LEN + 1)?;
    let raw = read_bytes(data, n)?;
    Self::from_bytes(raw).ok_or(DecodeError::BadLen {
      expected: vec![Sec1Byte::CompEven.size(), Sec1Byte::Uncomp.size()],
      actual: n,
    })
  }

  fn encode(&self, buf: &mut impl EncodeBuf) {
    let bytes = self.as_bytes();
    write_compact_size(bytes.len(), buf);
    buf.extend_from_slice(bytes); // nosemgrep: codec-no-raw-extend
  }
}

impl Debug for EcdsaPkBytes {
  fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
    write!(f, "EcdsaPkBytes({self})")
  }
}

impl Display for EcdsaPkBytes {
  fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
    for byte in self.as_bytes() {
      write!(f, "{:02x}", byte)?;
    }
    Ok(())
  }
}

impl Hashable for EcdsaPkBytes {
  type Hash = Hash160;

  fn hash(&self) -> Self::Hash {
    Self::Hash::from(*ripemd160::Hash::hash(sha256::Hash::hash(self.as_bytes()).as_ref()).as_byte_array())
  }
}

impl Ord for EcdsaPkBytes {
  fn cmp(&self, other: &Self) -> Ordering {
    self.as_bytes().cmp(other.as_bytes())
  }
}

impl PartialOrd for EcdsaPkBytes {
  fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
    Some(self.cmp(other))
  }
}

impl_type!(EcdsaPkBytes);

cfg_if! {
  if #[cfg(feature = "serde")] {
    use dash_types::serialize::hex as serde_hex;
    use serde::de::Error;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    impl Serialize for EcdsaPkBytes {
      fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serde_hex::serialize(self.as_bytes(), serializer)
      }
    }

    impl<'de> Deserialize<'de> for EcdsaPkBytes {
      fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Self::from_bytes(&serde_hex::deserialize(deserializer)?).ok_or_else(|| D::Error::custom("invalid public key"))
      }
    }
  }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "test code")]
mod tests {
  use super::{EcdsaPkBytes, Sec1Byte, ECDSA_PKCMP_LEN, ECDSA_PK_LEN};
  use crate::prelude::*;

  use hex_literal::hex;
  use rstest::*;

  const COMPRESSED_02: [u8; ECDSA_PKCMP_LEN] =
    hex!("02a1633cafcc01ebfb6d78e39f687a1f0995c62fc95f51ead10a02ee0be551b5dc");
  const COMPRESSED_03: [u8; ECDSA_PKCMP_LEN] =
    hex!("0379be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798");

  #[rstest]
  fn compressed_roundtrip() {
    let pk = EcdsaPkBytes::from_bytes(&COMPRESSED_02).unwrap();
    assert!(pk.is_compressed());
    assert_eq!(pk.size(), ECDSA_PKCMP_LEN);
    assert_eq!(pk.as_bytes(), &COMPRESSED_02);
  }

  #[rstest]
  fn display_is_hex() {
    let pk = EcdsaPkBytes::from_bytes(&COMPRESSED_02).unwrap();
    let s = format!("{pk}");
    assert_eq!(s.len(), ECDSA_PKCMP_LEN * 2);
    assert!(s.starts_with("02"));
  }

  #[rstest]
  #[case::comp_odd(0x03, true, Sec1Byte::CompOdd, ECDSA_PKCMP_LEN)]
  #[case::hybrid_even(0x06, false, Sec1Byte::UncompEven, ECDSA_PK_LEN + 1)]
  #[case::hybrid_odd(0x07, false, Sec1Byte::UncompOdd, ECDSA_PK_LEN + 1)]
  fn from_bytes_prefix(#[case] prefix: u8, #[case] compressed: bool, #[case] expected: Sec1Byte, #[case] len: usize) {
    let buf = [prefix; ECDSA_PK_LEN + 1];
    let pk = EcdsaPkBytes::from_bytes(&buf[..len]).unwrap();
    assert_eq!(pk.is_compressed(), compressed);
    assert_eq!(pk.prefix(), Some(expected));
  }

  #[rstest]
  #[case::bad_prefix(&[0x05; ECDSA_PK_LEN / 2])]
  #[case::wrong_length(&COMPRESSED_02[..32])]
  #[case::truncated(&[0x02u8] as &[u8])]
  fn from_bytes_rejects_invalid(#[case] input: &[u8]) {
    assert!(EcdsaPkBytes::from_bytes(input).is_none());
  }

  #[rstest]
  fn from_bytes_uncompressed() {
    let mut buf = [0x04u8; ECDSA_PK_LEN + 1];
    buf[1..33].copy_from_slice(&COMPRESSED_02[1..]);
    buf[33..].copy_from_slice(&[0xab; ECDSA_PK_LEN / 2]);
    let pk = EcdsaPkBytes::from_bytes(&buf).unwrap();
    assert!(!pk.is_compressed());
    assert_eq!(pk.size(), ECDSA_PK_LEN + 1);
    assert_eq!(pk.as_bytes(), &buf);
  }

  #[rstest]
  fn ordering_matches_bytes() {
    let a = EcdsaPkBytes::from_bytes(&COMPRESSED_02).unwrap();
    let b = EcdsaPkBytes::from_bytes(&COMPRESSED_03).unwrap();
    assert_eq!(a.cmp(&b), a.as_bytes().cmp(b.as_bytes()));
  }

  #[rstest]
  #[case(0x00)]
  #[case(0x05)]
  fn sec1_byte_rejects_invalid(#[case] byte: u8) {
    assert!(Sec1Byte::from_base(byte).is_none());
  }
}
