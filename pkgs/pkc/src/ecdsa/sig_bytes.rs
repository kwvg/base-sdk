//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! secp256k1 compact recoverable signature byte bag.

use crate::ecdsa::EcdsaError;
use crate::prelude::*;

use bitcoin_hashes::sha256d;
use cfg_if::cfg_if;
use dash_num::Hash256;
use dash_types::codec::{BaseCodec, DecodeError, EncodeBuf, Hashable};
use dash_types::{enum_map, impl_type, TypeId};

use core::fmt::{self, Debug, Formatter};

/// Raw secp256k1 signature (r || s) length.
pub const ECDSA_SIG_LEN: usize = 64;

enum_map! {
  /// Header flags for a compact recoverable ECDSA signature.
  #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
  pub(super) enum CompactFlags, u8 {
    /// Uncompressed key, recovery id 0.
    Uncompressed0 = 27,
    /// Uncompressed key, recovery id 1.
    Uncompressed1 = 28,
    /// Uncompressed key, recovery id 2.
    Uncompressed2 = 29,
    /// Uncompressed key, recovery id 3.
    Uncompressed3 = 30,
    /// Compressed key, recovery id 0.
    Compressed0 = 31,
    /// Compressed key, recovery id 1.
    Compressed1 = 32,
    /// Compressed key, recovery id 2.
    Compressed2 = 33,
    /// Compressed key, recovery id 3.
    Compressed3 = 34,
  }
}

impl CompactFlags {
  /// Whether the signing key was compressed.
  pub const fn is_compressed(self) -> bool {
    self.to_base() >= Self::Compressed0.to_base()
  }

  /// Construct from recovery id and compression flag.
  pub const fn new(recovery_id: u8, compressed: bool) -> Option<Self> {
    if recovery_id > 3 {
      return None;
    }
    let compressed_flag: u8 = if compressed { 4 } else { 0 };
    Self::from_base(Self::Uncompressed0.to_base() + recovery_id + compressed_flag)
  }

  /// Recovery ID.
  pub const fn recovery_id(self) -> u8 {
    (self.to_base() - Self::Uncompressed0.to_base()) & 3
  }
}

/// Raw compact recoverable ECDSA signature bytes.
#[derive(Clone, Copy, Eq, PartialEq, TypeId)]
pub struct EcdsaSigBytes([u8; ECDSA_SIG_LEN + 1]);

impl EcdsaSigBytes {
  /// The header flags.
  pub(super) fn flags(&self) -> Result<CompactFlags, EcdsaError> {
    CompactFlags::from_base(self.0[0]).ok_or(EcdsaError::InvalidCompactFlags)
  }

  /// Construct from compact bytes and pre-validated flags.
  pub(super) fn from_flags(sig: &[u8; ECDSA_SIG_LEN], flags: CompactFlags) -> Self {
    let mut buf = [0u8; ECDSA_SIG_LEN + 1];
    buf[0] = flags.to_base();
    buf[1..].copy_from_slice(sig);
    Self(buf)
  }

  /// The full 65-byte encoding.
  pub const fn as_bytes(&self) -> &[u8; ECDSA_SIG_LEN + 1] {
    &self.0
  }

  /// The headerless compact signature (r || s).
  pub fn compact(&self) -> [u8; ECDSA_SIG_LEN] {
    let mut out = [0u8; ECDSA_SIG_LEN];
    out.copy_from_slice(&self.0[1..]);
    out
  }

  /// Construct from components.
  pub fn from_parts(sig: &[u8; ECDSA_SIG_LEN], recovery_id: u8, compressed: bool) -> Option<Self> {
    let flags = CompactFlags::new(recovery_id, compressed)?;
    Some(Self::from_flags(sig, flags))
  }

  /// Construct from raw 65-byte buffer.
  pub const fn from_raw(bytes: [u8; ECDSA_SIG_LEN + 1]) -> Option<Self> {
    if CompactFlags::from_base(bytes[0]).is_some() {
      Some(Self(bytes))
    } else {
      None
    }
  }

  /// Whether the signing key was compressed.
  pub fn is_compressed(&self) -> Result<bool, EcdsaError> {
    self.flags().map(CompactFlags::is_compressed)
  }

  /// Recovery ID.
  pub fn recovery_id(&self) -> Result<u8, EcdsaError> {
    self.flags().map(CompactFlags::recovery_id)
  }
}

impl BaseCodec for EcdsaSigBytes {
  fn decode(data: &mut &[u8]) -> Result<Self, DecodeError> {
    let arr = <[u8; ECDSA_SIG_LEN + 1]>::decode(data)?;
    Self::from_raw(arr).ok_or_else(|| DecodeError::InvalidValue {
      expected: CompactFlags::variants()
        .iter()
        .map(|f| u64::from(f.to_base()))
        .collect(),
      actual: u64::from(arr[0]),
    })
  }

  fn encode(&self, buf: &mut impl EncodeBuf) {
    self.0.encode(buf);
  }
}

impl Debug for EcdsaSigBytes {
  fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
    match self.flags() {
      Ok(flags) => write!(
        f,
        "EcdsaSigBytes(recid={}, compressed={})",
        flags.recovery_id(),
        flags.is_compressed()
      ),
      Err(e) => write!(f, "EcdsaSigBytes(<invalid: {e}>)"),
    }
  }
}

impl Hashable for EcdsaSigBytes {
  type Hash = Hash256;

  fn hash(&self) -> Hash256 {
    let mut buf = Vec::new();
    self.encode(&mut buf);
    Hash256::from_bytes(sha256d::Hash::hash(&buf).to_byte_array())
  }
}

impl_type!(EcdsaSigBytes);

cfg_if! {
  if #[cfg(feature = "serde")] {
    use serde::{Serialize, Serializer, Deserialize, Deserializer, de::Error as DeError};
    use hex_conservative::{DisplayHex, FromHex};

    impl Serialize for EcdsaSigBytes {
      fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0.to_lower_hex_string())
      }
    }

    impl<'de> Deserialize<'de> for EcdsaSigBytes {
      fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = <String as Deserialize>::deserialize(deserializer)?;
        let arr = <[u8; ECDSA_SIG_LEN + 1] as FromHex>::from_hex(&s).map_err(DeError::custom)?;
        Self::from_raw(arr).ok_or_else(|| DeError::custom("invalid compact signature header"))
      }
    }
  }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "test code")]
mod tests {
  use super::{CompactFlags, EcdsaSigBytes, ECDSA_SIG_LEN};

  use rstest::*;

  #[rstest]
  #[case::compressed(0xab, 1, true, CompactFlags::Compressed1)]
  #[case::uncompressed(0xcd, 0, false, CompactFlags::Uncompressed0)]
  fn from_parts_roundtrip(
    #[case] fill: u8,
    #[case] rid: u8,
    #[case] compressed: bool,
    #[case] expected_flags: CompactFlags,
  ) {
    let sig = [fill; ECDSA_SIG_LEN];
    let sb = EcdsaSigBytes::from_parts(&sig, rid, compressed).unwrap();
    assert_eq!(sb.compact(), sig);
    assert_eq!(sb.recovery_id().unwrap(), rid);
    assert_eq!(sb.is_compressed().unwrap(), compressed);
    assert_eq!(sb.flags().unwrap(), expected_flags);
  }

  #[rstest]
  fn from_raw_rejects_bad_header() {
    let mut buf = [0u8; ECDSA_SIG_LEN + 1];
    buf[0] = 0x00;
    assert!(EcdsaSigBytes::from_raw(buf).is_none());

    buf[0] = CompactFlags::Compressed3.to_base() + 1;
    assert!(EcdsaSigBytes::from_raw(buf).is_none());
  }

  #[rstest]
  fn from_raw_valid() {
    let mut buf = [0u8; ECDSA_SIG_LEN + 1];
    buf[0] = CompactFlags::Compressed2.to_base();
    let sb = EcdsaSigBytes::from_raw(buf).unwrap();
    assert_eq!(sb.recovery_id().unwrap(), 2);
    assert!(sb.is_compressed().unwrap());
  }

  #[rstest]
  #[case(0, false)]
  #[case(0, true)]
  #[case(1, false)]
  #[case(1, true)]
  #[case(2, false)]
  #[case(2, true)]
  #[case(3, false)]
  #[case(3, true)]
  fn flags_roundtrip(#[case] rid: u8, #[case] compressed: bool) {
    let flags = CompactFlags::new(rid, compressed).unwrap();
    assert_eq!(flags.recovery_id(), rid);
    assert_eq!(flags.is_compressed(), compressed);
    assert_eq!(CompactFlags::from_base(flags.to_base()), Some(flags));
  }

  #[rstest]
  fn header_byte_encoding() {
    let sb = EcdsaSigBytes::from_parts(&[0; ECDSA_SIG_LEN], 1, true).unwrap();
    assert_eq!(sb.as_bytes()[0], CompactFlags::Compressed1.to_base());

    let sb = EcdsaSigBytes::from_parts(&[0; ECDSA_SIG_LEN], 3, false).unwrap();
    assert_eq!(sb.as_bytes()[0], CompactFlags::Uncompressed3.to_base());
  }

  #[rstest]
  #[case::valid_0(0, true)]
  #[case::valid_1(1, true)]
  #[case::valid_2(2, true)]
  #[case::valid_3(3, true)]
  #[case::out_of_range_4(4, false)]
  #[case::out_of_range_255(255, false)]
  fn recovery_id_range(#[case] rid: u8, #[case] valid: bool) {
    let result = EcdsaSigBytes::from_parts(&[0; ECDSA_SIG_LEN], rid, true);
    assert_eq!(result.is_some(), valid);
    if let Some(sb) = result {
      assert_eq!(sb.recovery_id().unwrap(), rid);
    }
  }
}
