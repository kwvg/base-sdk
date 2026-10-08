//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Scheme-tagged BLS public keys and signatures.

use crate::payload::PROTX_VERSION_LEGACY_BLS;

use dash_pkc::bls::{BlsPkBytes, BlsScChia, BlsScIetf, BlsSigBytes, BLS_PK_LEN, BLS_SIG_LEN};
use dash_types::codec::{BaseCodec, DecodeError, EncodeBuf};
use dash_types::type_id::Unencodable;
#[cfg(feature = "serde")]
use hex_conservative::DisplayHex;

/// Encoding of a BLS point on the wire.
///
/// The two encodings read the leading byte differently, so bytes decoded in
/// the wrong scheme name a different point or none.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Unencodable)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub enum BlsScheme {
  /// Legacy (Chia) encoding.
  Legacy,
  /// Basic (IETF) encoding.
  Basic,
}

impl BlsScheme {
  /// Scheme of the BLS fields in a ProTx payload of `version`.
  pub const fn from_protx_version(version: u16) -> Self {
    if version == PROTX_VERSION_LEGACY_BLS {
      Self::Legacy
    } else {
      Self::Basic
    }
  }

  /// Scheme of the BLS fields in a final commitment of `version`. Versions 1
  /// and 2 use the legacy scheme; later versions use basic.
  pub const fn from_commitment_version(version: u16) -> Self {
    if matches!(version, 1 | 2) {
      Self::Legacy
    } else {
      Self::Basic
    }
  }
}

/// Declares a scheme-tagged wrapper over a pkc BLS byte bag.
macro_rules! bls_tagged {
  (
    $(#[$attr:meta])*
    $name:ident, $bag:ident, $len:ident
  ) => {
    $(#[$attr])*
    ///
    /// The wire image holds only the bytes. Containers take the scheme from
    /// their own version, so there is no scheme-free decoder.
    #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Unencodable)]
    pub enum $name {
      /// Legacy (Chia) encoding.
      Legacy($bag<BlsScChia>),
      /// Basic (IETF) encoding.
      Basic($bag<BlsScIetf>),
    }

    /// Serializes as bare hex. There is no `Deserialize`, because the JSON
    /// image carries no scheme; containers restore it from their version.
    #[cfg(feature = "serde")]
    impl ::serde::Serialize for $name {
      fn serialize<Z: ::serde::Serializer>(&self, serializer: Z) -> Result<Z::Ok, Z::Error> {
        serializer.serialize_str(&self.as_bytes().to_lower_hex_string())
      }
    }

    impl $name {
      /// Tags raw bytes with `scheme`.
      pub const fn from_bytes(bytes: [u8; $len], scheme: BlsScheme) -> Self {
        match scheme {
          BlsScheme::Legacy => Self::Legacy($bag::from_bytes(bytes)),
          BlsScheme::Basic => Self::Basic($bag::from_bytes(bytes)),
        }
      }

      /// Reads the bytes and tags them with `scheme`.
      ///
      /// # Errors
      ///
      /// Returns [`DecodeError::Eof`] when too few bytes remain.
      pub fn decode(data: &mut &[u8], scheme: BlsScheme) -> Result<Self, DecodeError> {
        Ok(match scheme {
          BlsScheme::Legacy => Self::Legacy($bag::decode(data)?),
          BlsScheme::Basic => Self::Basic($bag::decode(data)?),
        })
      }

      /// Writes the bytes.
      pub fn encode(&self, buf: &mut impl EncodeBuf) {
        match self {
          Self::Legacy(bytes) => bytes.encode(buf),
          Self::Basic(bytes) => bytes.encode(buf),
        }
      }

      /// Scheme the bytes are encoded in.
      pub const fn scheme(&self) -> BlsScheme {
        match self {
          Self::Legacy(_) => BlsScheme::Legacy,
          Self::Basic(_) => BlsScheme::Basic,
        }
      }

      /// Raw bytes.
      pub const fn as_bytes(&self) -> &[u8; $len] {
        match self {
          Self::Legacy(bytes) => bytes.as_bytes(),
          Self::Basic(bytes) => bytes.as_bytes(),
        }
      }

      /// Tells whether every byte is zero.
      pub fn is_null(&self) -> bool {
        self.as_bytes().iter().all(|&byte| byte == 0)
      }
    }
  };
}

bls_tagged! {
  /// BLS public key tagged with its encoding scheme.
  BlsPubKey, BlsPkBytes, BLS_PK_LEN
}

bls_tagged! {
  /// BLS signature tagged with its encoding scheme.
  BlsSig, BlsSigBytes, BLS_SIG_LEN
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "test code")]
mod tests {
  use super::{BlsPubKey, BlsScheme, BlsSig};
  use crate::prelude::*;

  use dash_pkc::bls::{BLS_PK_LEN, BLS_SIG_LEN};
  use rstest::rstest;

  #[rstest]
  #[case::v0(0, BlsScheme::Basic)]
  #[case::v1(1, BlsScheme::Legacy)]
  #[case::v2(2, BlsScheme::Basic)]
  #[case::v3(3, BlsScheme::Basic)]
  fn protx_version_selects_the_scheme(#[case] version: u16, #[case] scheme: BlsScheme) {
    assert_eq!(BlsScheme::from_protx_version(version), scheme);
  }

  #[rstest]
  #[case::v1(1, BlsScheme::Legacy)]
  #[case::v2(2, BlsScheme::Legacy)]
  #[case::v3(3, BlsScheme::Basic)]
  #[case::v4(4, BlsScheme::Basic)]
  fn commitment_version_selects_the_scheme(#[case] version: u16, #[case] scheme: BlsScheme) {
    assert_eq!(BlsScheme::from_commitment_version(version), scheme);
  }

  #[rstest]
  #[case::legacy(BlsScheme::Legacy)]
  #[case::basic(BlsScheme::Basic)]
  fn pub_key_round_trips_with_its_tag(#[case] scheme: BlsScheme) {
    let raw = [0xA3; BLS_PK_LEN];
    let key = BlsPubKey::from_bytes(raw, scheme);
    let mut buf = Vec::new();
    key.encode(&mut buf);
    assert_eq!(buf, raw);

    let back = BlsPubKey::decode(&mut buf.as_slice(), scheme).unwrap();
    assert_eq!((back, back.scheme(), back.as_bytes()), (key, scheme, &raw));
  }

  #[rstest]
  #[case::legacy(BlsScheme::Legacy)]
  #[case::basic(BlsScheme::Basic)]
  fn sig_round_trips_with_its_tag(#[case] scheme: BlsScheme) {
    let raw = [0x5C; BLS_SIG_LEN];
    let sig = BlsSig::from_bytes(raw, scheme);
    let mut buf = Vec::new();
    sig.encode(&mut buf);
    assert_eq!(buf, raw);

    let back = BlsSig::decode(&mut buf.as_slice(), scheme).unwrap();
    assert_eq!((back, back.scheme(), back.as_bytes()), (sig, scheme, &raw));
  }

  #[rstest]
  fn tags_differ_for_equal_bytes() {
    let raw = [0x11; BLS_PK_LEN];
    assert_ne!(
      BlsPubKey::from_bytes(raw, BlsScheme::Legacy),
      BlsPubKey::from_bytes(raw, BlsScheme::Basic)
    );
  }

  #[rstest]
  fn short_input_is_eof() {
    let raw = [0x11; BLS_SIG_LEN - 1];
    assert!(matches!(
      BlsSig::decode(&mut raw.as_slice(), BlsScheme::Basic),
      Err(dash_types::codec::DecodeError::Eof { .. })
    ));
  }

  #[rstest]
  fn null_is_all_zero() {
    assert!(BlsPubKey::from_bytes([0; BLS_PK_LEN], BlsScheme::Basic).is_null());
    assert!(!BlsSig::from_bytes([1; BLS_SIG_LEN], BlsScheme::Legacy).is_null());
  }

  #[cfg(feature = "serde")]
  #[rstest]
  #[case::legacy(BlsScheme::Legacy)]
  #[case::basic(BlsScheme::Basic)]
  fn serializes_as_bare_hex(#[case] scheme: BlsScheme) {
    let key = BlsPubKey::from_bytes([0xAB; BLS_PK_LEN], scheme);
    assert_eq!(dash_dev::to_json(&key), format!("\"{}\"", "ab".repeat(BLS_PK_LEN)));
  }
}
