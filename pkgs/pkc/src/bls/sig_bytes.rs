//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! BLS signature byte bag parameterized by scheme.

use crate::bls::BlsSchemeId;

use bitcoin_consensus_encoding::{Decodable, Encodable};
use bitcoin_hashes::sha256d;
use cfg_if::cfg_if;
use dash_num::Hash256;
use dash_types::codec::{take, BaseCodec, DecodeError, EncodeBuf, Hashable, TypeId};
use dash_types::{BufferDecoder, VecEncoder};

use core::cmp::Ordering;
use core::fmt::{self, Debug, Display, Formatter};
use core::hash::{Hash, Hasher};
use core::marker::PhantomData;

/// Raw BLS signature length (G2 compressed).
pub const BLS_SIG_LEN: usize = 96;

/// Scheme-tagged BLS signature bytes (96 bytes, unvalidated).
pub struct BlsSigBytes<S: BlsSchemeId> {
  inner: [u8; BLS_SIG_LEN],
  _scheme: PhantomData<S>,
}

impl<S: BlsSchemeId> BlsSigBytes<S> {
  /// Wraps raw bytes without validation.
  pub const fn from_bytes(bytes: [u8; BLS_SIG_LEN]) -> Self {
    Self {
      inner: bytes,
      _scheme: PhantomData,
    }
  }

  /// Borrows the inner byte array.
  pub const fn as_bytes(&self) -> &[u8; BLS_SIG_LEN] {
    &self.inner
  }

  /// Returns the inner byte array.
  pub const fn to_bytes(self) -> [u8; BLS_SIG_LEN] {
    self.inner
  }

  /// Returns `true` when every byte is zero.
  pub fn is_null(&self) -> bool {
    self.inner.iter().all(|&b| b == 0)
  }
}

impl<S: BlsSchemeId> Clone for BlsSigBytes<S> {
  fn clone(&self) -> Self {
    *self
  }
}

impl<S: BlsSchemeId> Copy for BlsSigBytes<S> {}

impl<S: BlsSchemeId> Eq for BlsSigBytes<S> {}

impl<S: BlsSchemeId> PartialEq for BlsSigBytes<S> {
  fn eq(&self, other: &Self) -> bool {
    self.inner == other.inner
  }
}

impl<S: BlsSchemeId> Hash for BlsSigBytes<S> {
  fn hash<H: Hasher>(&self, state: &mut H) {
    self.inner.hash(state);
  }
}

impl<S: BlsSchemeId> AsRef<[u8]> for BlsSigBytes<S> {
  fn as_ref(&self) -> &[u8] {
    &self.inner
  }
}

impl<S: BlsSchemeId> AsRef<[u8; BLS_SIG_LEN]> for BlsSigBytes<S> {
  fn as_ref(&self) -> &[u8; BLS_SIG_LEN] {
    &self.inner
  }
}

impl<S: BlsSchemeId> Default for BlsSigBytes<S> {
  fn default() -> Self {
    Self::from_bytes([0u8; BLS_SIG_LEN])
  }
}

impl<S: BlsSchemeId> From<[u8; BLS_SIG_LEN]> for BlsSigBytes<S> {
  fn from(bytes: [u8; BLS_SIG_LEN]) -> Self {
    Self::from_bytes(bytes)
  }
}

impl<S: BlsSchemeId> From<BlsSigBytes<S>> for [u8; BLS_SIG_LEN] {
  fn from(val: BlsSigBytes<S>) -> Self {
    val.inner
  }
}

impl<S: BlsSchemeId> TypeId for BlsSigBytes<S> {
  const TYPE_ID: u32 = S::SIG_TYPE_ID;
}

impl<S: BlsSchemeId> BaseCodec for BlsSigBytes<S> {
  fn decode(data: &mut &[u8]) -> Result<Self, DecodeError> {
    take::<BLS_SIG_LEN>(data).map(Self::from_bytes)
  }

  fn encode(&self, buf: &mut impl EncodeBuf) {
    buf.extend_from_slice(&self.inner);
  }
}

impl<S: BlsSchemeId> Encodable for BlsSigBytes<S> {
  type Encoder<'e> = VecEncoder;
  fn encoder(&self) -> Self::Encoder<'_> {
    let mut buf = alloc::vec::Vec::new();
    BaseCodec::encode(self, &mut buf);
    VecEncoder::new(buf)
  }
}

impl<S: BlsSchemeId> Decodable for BlsSigBytes<S> {
  type Decoder = BufferDecoder<Self>;
  fn decoder() -> Self::Decoder {
    BufferDecoder::new(<Self as BaseCodec>::decode, dash_types::MAX_SER_SIZE)
  }
}

impl<S: BlsSchemeId> Debug for BlsSigBytes<S> {
  fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
    write!(f, "BlsSigBytes<{}>(", S::LABEL)?;
    for byte in &self.inner {
      write!(f, "{byte:02x}")?;
    }
    write!(f, ")")
  }
}

impl<S: BlsSchemeId> Display for BlsSigBytes<S> {
  fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
    for byte in &self.inner {
      write!(f, "{byte:02x}")?;
    }
    Ok(())
  }
}

impl<S: BlsSchemeId> Hashable for BlsSigBytes<S> {
  type Hash = Hash256;

  fn hash(&self) -> Self::Hash {
    Self::Hash::from_bytes(sha256d::Hash::hash(&self.inner).to_byte_array())
  }
}

impl<S: BlsSchemeId> Ord for BlsSigBytes<S> {
  fn cmp(&self, other: &Self) -> Ordering {
    self.inner.cmp(&other.inner)
  }
}

impl<S: BlsSchemeId> PartialOrd for BlsSigBytes<S> {
  fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
    Some(self.cmp(other))
  }
}

cfg_if! {
  if #[cfg(feature = "serde")] {
    use hex_conservative::{DisplayHex, FromHex};
    use serde::de::Error;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    impl<S: BlsSchemeId> Serialize for BlsSigBytes<S> {
      fn serialize<Z: Serializer>(&self, serializer: Z) -> Result<Z::Ok, Z::Error> {
        serializer.serialize_str(&self.inner.to_lower_hex_string())
      }
    }

    impl<'de, S: BlsSchemeId> Deserialize<'de> for BlsSigBytes<S> {
      fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = <alloc::string::String as Deserialize>::deserialize(deserializer)?;
        <[u8; BLS_SIG_LEN] as FromHex>::from_hex(&s)
          .map(Self::from_bytes)
          .map_err(Error::custom)
      }
    }
  }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "test code")]
mod tests {
  use super::{BlsSigBytes, BLS_SIG_LEN};
  use crate::bls::{BlsScChia, BlsScIetf};
  use crate::prelude::*;

  use dash_types::codec::TypeId;
  use hex_literal::hex;
  use rstest::*;

  const SAMPLE: [u8; BLS_SIG_LEN] = hex!(
    "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6"
    "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6"
    "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6"
    "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6"
  );

  #[rstest]
  fn roundtrip() {
    let sig = BlsSigBytes::<BlsScChia>::from_bytes(SAMPLE);
    assert_eq!(*sig.as_bytes(), SAMPLE);
    assert_eq!(sig.to_bytes(), SAMPLE);
  }

  #[rstest]
  fn distinct_type_ids() {
    assert_ne!(BlsSigBytes::<BlsScChia>::TYPE_ID, BlsSigBytes::<BlsScIetf>::TYPE_ID,);
  }

  #[rstest]
  fn display_is_hex() {
    let sig = BlsSigBytes::<BlsScIetf>::from_bytes(SAMPLE);
    let s = format!("{sig}");
    assert_eq!(s.len(), BLS_SIG_LEN * 2);
  }

  #[rstest]
  fn debug_includes_scheme() {
    let sig = BlsSigBytes::<BlsScChia>::from_bytes([0u8; BLS_SIG_LEN]);
    let dbg = format!("{sig:?}");
    assert!(dbg.starts_with("BlsSigBytes<Chia>("));
  }

  #[rstest]
  fn null_check() {
    assert!(BlsSigBytes::<BlsScIetf>::default().is_null());
    assert!(!BlsSigBytes::<BlsScIetf>::from_bytes(SAMPLE).is_null());
  }

  #[rstest]
  fn ordering() {
    let a = BlsSigBytes::<BlsScChia>::from_bytes([0x01; BLS_SIG_LEN]);
    let b = BlsSigBytes::<BlsScChia>::from_bytes([0x02; BLS_SIG_LEN]);
    assert!(a < b);
  }

  #[rstest]
  fn from_array() {
    let sig: BlsSigBytes<BlsScIetf> = SAMPLE.into();
    let arr: [u8; BLS_SIG_LEN] = sig.into();
    assert_eq!(arr, SAMPLE);
  }

  cfg_if::cfg_if! {
    if #[cfg(feature = "serde")] {
      #[rstest]
      fn serde_roundtrip() {
        let sig = BlsSigBytes::<BlsScIetf>::from_bytes(SAMPLE);
        let json = serde_json::to_string(&sig).unwrap();
        let decoded: BlsSigBytes<BlsScIetf> = serde_json::from_str(&json).unwrap();
        assert_eq!(sig, decoded);
      }
    }
  }
}
