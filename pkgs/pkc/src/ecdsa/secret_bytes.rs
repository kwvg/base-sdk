//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! secp256k1 secret key byte bag.

use crate::prelude::*;

use base58ck::{decode_check, encode_check};
use cfg_if::cfg_if;
use dash_types::type_cvrt;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use core::fmt::{self, Debug, Display, Formatter};

/// Raw secp256k1 secret key length.
pub const ECDSA_SK_LEN: usize = 32;

/// Raw ECDSA secret key bytes.
///
/// Carries a compression flag that determines the serialization format of
/// the corresponding public key.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
#[cfg_attr(feature = "k256", derive(TypeId))]
pub struct EcdsaSkBytes {
  inner: [u8; ECDSA_SK_LEN],
  #[zeroize(skip)]
  compressed: bool,
}

impl EcdsaSkBytes {
  /// Borrow the raw inner bytes.
  pub const fn as_bytes(&self) -> &[u8; ECDSA_SK_LEN] {
    &self.inner
  }

  /// Wrap raw bytes with a compression flag.
  pub const fn from_bytes(bytes: [u8; ECDSA_SK_LEN], compressed: bool) -> Self {
    Self {
      inner: bytes,
      compressed,
    }
  }

  /// Whether the corresponding public key should be compressed.
  pub const fn is_compressed(&self) -> bool {
    self.compressed
  }

  /// Decode a wallet import format-encoded private key.
  pub fn from_wif(s: &str, prefix: u8) -> Option<Self> {
    let data = Zeroizing::new(decode_check(s).ok()?);
    let result = match data.len() {
      33 if data[0] == prefix => {
        let key: [u8; ECDSA_SK_LEN] = data[1..33].try_into().ok()?;
        Some(Self::from_bytes(key, false))
      }
      34 if data[0] == prefix && data[33] == 0x01 => {
        let key: [u8; ECDSA_SK_LEN] = data[1..33].try_into().ok()?;
        Some(Self::from_bytes(key, true))
      }
      _ => None,
    };
    result.filter(|sk| !sk.is_null())
  }

  /// Returns `true` when every byte is zero.
  pub fn is_null(&self) -> bool {
    self.inner.ct_eq(&[0u8; ECDSA_SK_LEN]).into()
  }

  /// Copy out the raw inner bytes.
  pub fn to_bytes(&self) -> Zeroizing<[u8; ECDSA_SK_LEN]> {
    Zeroizing::new(self.inner)
  }

  /// Encode as a wallet import format string.
  pub fn to_wif(&self, prefix: u8) -> String {
    let mut buf = Zeroizing::new([0u8; 34]);
    buf[0] = prefix;
    buf[1..33].copy_from_slice(&self.inner);
    if self.compressed {
      buf[33] = 0x01;
      encode_check(&buf[..34])
    } else {
      encode_check(&buf[..33])
    }
  }
}

impl AsRef<[u8; ECDSA_SK_LEN]> for EcdsaSkBytes {
  fn as_ref(&self) -> &[u8; ECDSA_SK_LEN] {
    &self.inner
  }
}

impl Debug for EcdsaSkBytes {
  fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
    write!(f, "EcdsaSkBytes(..)")
  }
}

impl Display for EcdsaSkBytes {
  fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
    Debug::fmt(self, f)
  }
}

impl Eq for EcdsaSkBytes {}

impl PartialEq for EcdsaSkBytes {
  fn eq(&self, other: &Self) -> bool {
    self.inner.ct_eq(&other.inner).into() && self.compressed == other.compressed
  }
}

type_cvrt!(From<[u8; ECDSA_SK_LEN]> for EcdsaSkBytes, |v| {
  Self::from_bytes(*v, true)
});

cfg_if! {
  if #[cfg(feature = "k256")] {
    use crate::ecdsa::EcdsaError;
    use bitcoin_hashes::sha256d;
    use dash_num::Hash256;
    use dash_types::codec::{ensure, BaseCodec, DecodeError, EncodeBuf, Hashable};
    use dash_types::{impl_type, TypeId, MAX_SER_SIZE};
    use hex_literal::hex;
    use k256::{elliptic_curve::sec1::ToEncodedPoint, AffinePoint, SecretKey};

    const DER_SIZES: &[usize] = &[214, 279];
    const OID_PRIME_FIELD: &[u8] = &hex!("2a8648ce3d0101");
    const PRIME: &[u8; ECDSA_SK_LEN] = &hex!("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f");
    const ORDER: &[u8; ECDSA_SK_LEN] = &hex!("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141");

    fn der_bytes(buf: &mut impl EncodeBuf, tag: u8, bytes: &[u8]) {
      der_header(buf, tag, bytes.len());
      buf.extend_from_slice(bytes);
    }

    fn der_header(buf: &mut impl EncodeBuf, tag: u8, len: usize) {
      let [hi, lo] = (len as u16).to_be_bytes();
      match len {
        0..=0x7f => buf.extend_from_slice(&[tag, lo]),
        0x80..=0xff => buf.extend_from_slice(&[tag, 0x81, lo]),
        _ => buf.extend_from_slice(&[tag, 0x82, hi, lo]),
      }
    }

    fn der_uint(buf: &mut impl EncodeBuf, bytes: &[u8]) {
      der_header(buf, 2, bytes.len() + usize::from(bytes[0] >= 0x80));
      if bytes[0] >= 0x80 {
        buf.push(0);
      }
      buf.extend_from_slice(bytes);
    }

    impl BaseCodec<EcdsaError> for EcdsaSkBytes {
      fn decode(data: &mut &[u8]) -> Result<Self, DecodeError<EcdsaError>> {
        ensure(data, 4).map_err(|e| e.lift())?;
        if data[0] != 0x30 {
          return Err(DecodeError::DecError(EcdsaError::MalformedDer));
        }
        let (len, off) = match data[1] {
          0x81 => (usize::from(data[2]) + 3, 3),
          0x82 => ((usize::from(data[2]) << 8 | usize::from(data[3])) + 4, 4),
          _ => return Err(DecodeError::DecError(EcdsaError::MalformedDer)),
        };
        let compressed = len == DER_SIZES[0];
        if !DER_SIZES.contains(&len) {
          return Err(DecodeError::BadLen {
            expected: DER_SIZES.to_vec(),
            actual: len,
          });
        }
        if data.len() < len {
          return Err(DecodeError::Eof {
            needed: len,
            remaining: data.len(),
          });
        }
        if data[off..off + 5] != [2, 1, 1, 4, 32] {
          return Err(DecodeError::DecError(EcdsaError::MalformedDer));
        }
        let mut key = Zeroizing::new([0; ECDSA_SK_LEN]);
        key.copy_from_slice(&data[off + 5..off + 5 + ECDSA_SK_LEN]);
        *data = &data[len..];
        Ok(EcdsaSkBytes::from_bytes(*key, compressed))
      }

      fn encode(&self, buf: &mut impl EncodeBuf) {
        let Some(secret) = SecretKey::from_bytes((&self.inner).into()).ok() else {
          debug_assert!(false, "DER encoding failed for invalid key");
          return;
        };
        let pk = secret.public_key();
        let public = pk.to_encoded_point(self.compressed);
        let public = public.as_bytes();
        let generator = AffinePoint::GENERATOR.to_encoded_point(self.compressed);
        let generator = generator.as_bytes();
        let point_len = public.len();
        let params_len = point_len + 97;

        der_header(buf, 0x30, 2 * point_len + 145);
        der_uint(buf, &[1]);
        der_bytes(buf, 4, &self.inner);
        der_header(buf, 0xa0, params_len + 3);
        der_header(buf, 0x30, params_len);
        der_uint(buf, &[1]);
        der_header(buf, 0x30, 44);
        der_bytes(buf, 6, OID_PRIME_FIELD);
        der_uint(buf, PRIME);
        der_header(buf, 0x30, 6);
        der_bytes(buf, 4, &[0]);
        der_bytes(buf, 4, &[7]);
        der_bytes(buf, 4, generator);
        der_uint(buf, ORDER);
        der_uint(buf, &[1]);
        der_header(buf, 0xa1, point_len + 3);
        der_header(buf, 3, point_len + 1);
        buf.push(0);
        buf.extend_from_slice(public);
      }
    }

    impl Hashable for EcdsaSkBytes {
      type Hash = Hash256;

      fn hash(&self) -> Self::Hash {
        let mut buf = Zeroizing::new(Vec::new());
        self.encode(&mut *buf);
        Self::Hash::from_bytes(sha256d::Hash::hash(&buf).to_byte_array())
      }
    }

    impl_type!(EcdsaSkBytes, MAX_SER_SIZE, EcdsaError);
  }
}

cfg_if! {
  if #[cfg(feature = "serde")] {
    use hex_conservative::{DisplayHex, FromHex};
    use serde::{Serialize, Serializer, Deserialize, Deserializer, de::Error as DeError};

    impl Serialize for EcdsaSkBytes {
      fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.inner.to_lower_hex_string().serialize(serializer)
      }
    }

    impl<'de> Deserialize<'de> for EcdsaSkBytes {
      fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        // Defaults to compressed; compression flag is not encoded in the hex representation.
        let sk = <[u8; ECDSA_SK_LEN] as FromHex>::from_hex(&s)
          .map(|b| Self::from_bytes(b, true))
          .map_err(DeError::custom)?;
        if sk.is_null() {
          return Err(DeError::custom("null secret key"));
        }
        Ok(sk)
      }
    }
  }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "test code")]
mod tests {
  use super::{cfg_if, EcdsaSkBytes, ECDSA_SK_LEN};
  use crate::prelude::*;

  use rstest::*;

  #[rstest]
  fn debug_redacts_inner() {
    let sk = EcdsaSkBytes::from_bytes([0xffu8; ECDSA_SK_LEN], true);
    let dbg = format!("{sk:?}");
    assert_eq!(dbg, "EcdsaSkBytes(..)");
    assert!(!dbg.contains("ff"));
  }

  #[rstest]
  fn equality() {
    let a = EcdsaSkBytes::from_bytes([1u8; ECDSA_SK_LEN], true);
    let b = EcdsaSkBytes::from_bytes([1u8; ECDSA_SK_LEN], true);
    let c = EcdsaSkBytes::from_bytes([2u8; ECDSA_SK_LEN], true);
    let d = EcdsaSkBytes::from_bytes([1u8; ECDSA_SK_LEN], false);
    assert_eq!(a, b);
    assert_ne!(a, c);
    assert_ne!(a, d, "same scalar but different compression");
  }

  #[rstest]
  #[case::compressed(0x42, true)]
  #[case::uncompressed(0x01, false)]
  fn roundtrip(#[case] fill: u8, #[case] compressed: bool) {
    let bytes = [fill; ECDSA_SK_LEN];
    let sk = EcdsaSkBytes::from_bytes(bytes, compressed);
    assert_eq!(*sk.to_bytes(), bytes);
    assert_eq!(sk.as_bytes(), &bytes);
    assert_eq!(sk.is_compressed(), compressed);
  }

  #[rstest]
  fn wif_rejects_zero_key() {
    // Encode a zero key into WIF manually, then verify from_wif
    // rejects it.
    let zero = EcdsaSkBytes::from_bytes([0u8; ECDSA_SK_LEN], true);
    let wif = zero.to_wif(0x80);
    assert!(EcdsaSkBytes::from_wif(&wif, 0x80).is_none());
  }

  cfg_if! {
    if #[cfg(feature = "k256")] {
      use dash_types::codec::BaseCodec;

      #[rstest]
      #[case::compressed(true)]
      #[case::uncompressed(false)]
      fn codec_roundtrip_preserves_compression(#[case] compressed: bool) {
        let sk = EcdsaSkBytes::from_bytes([0x42u8; ECDSA_SK_LEN], compressed);
        let mut buf = Vec::new();
        sk.encode(&mut buf);
        let decoded = EcdsaSkBytes::decode(&mut buf.as_slice()).unwrap();
        assert_eq!(decoded.as_bytes(), sk.as_bytes());
        assert_eq!(decoded.is_compressed(), compressed);
      }
    }
  }

  cfg_if! {
    if #[cfg(feature = "serde")] {
      #[rstest]
      fn serde_roundtrip_defaults_compressed() {
        let sk = EcdsaSkBytes::from_bytes([0x42u8; ECDSA_SK_LEN], true);
        let json = serde_json::to_string(&sk).unwrap();
        let decoded: EcdsaSkBytes = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.as_bytes(), sk.as_bytes());
        assert!(decoded.is_compressed());
      }

      #[rstest]
      fn serde_rejects_null_key() {
        let json = format!("\"{}\"", "00".repeat(ECDSA_SK_LEN));
        assert!(serde_json::from_str::<EcdsaSkBytes>(&json).is_err());
      }
    }
  }
}
