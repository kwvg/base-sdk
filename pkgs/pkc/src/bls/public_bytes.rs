//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! BLS public key byte bag parameterized by scheme.

use crate::bls::BlsSchemeId;
use crate::prelude::*;

use bitcoin_consensus_encoding::{Decodable, Encodable};
use bitcoin_hashes::ripemd160::Hash as Ripemd160;
use bitcoin_hashes::sha256::Hash as Sha256;
use cfg_if::cfg_if;
use dash_num::Hash160;
use dash_types::codec::{take, BaseCodec, DecodeError, EncodeBuf, Hashable, TypeId};
use dash_types::{BufferDecoder, VecEncoder, MAX_SER_SIZE};

use core::cmp::Ordering;
use core::fmt::{Debug, Display, Formatter, Result as FmtResult};
use core::hash::{Hash, Hasher};
use core::marker::PhantomData;

/// Raw BLS public key length (G1 compressed).
pub const BLS_PK_LEN: usize = 48;

/// Scheme-tagged BLS public key bytes (48 bytes, unvalidated).
pub struct BlsPkBytes<S: BlsSchemeId> {
  inner: [u8; BLS_PK_LEN],
  _scheme: PhantomData<S>,
}

impl<S: BlsSchemeId> BlsPkBytes<S> {
  /// Wraps raw bytes without validation.
  pub const fn from_bytes(bytes: [u8; BLS_PK_LEN]) -> Self {
    Self {
      inner: bytes,
      _scheme: PhantomData,
    }
  }

  /// Borrows the inner byte array.
  pub const fn as_bytes(&self) -> &[u8; BLS_PK_LEN] {
    &self.inner
  }

  /// Returns the inner byte array.
  pub const fn to_bytes(self) -> [u8; BLS_PK_LEN] {
    self.inner
  }

  /// Returns `true` when every byte is zero.
  pub fn is_null(&self) -> bool {
    self.inner.iter().all(|&b| b == 0)
  }
}

impl<S: BlsSchemeId> Clone for BlsPkBytes<S> {
  fn clone(&self) -> Self {
    *self
  }
}

impl<S: BlsSchemeId> Copy for BlsPkBytes<S> {}

impl<S: BlsSchemeId> Eq for BlsPkBytes<S> {}

impl<S: BlsSchemeId> PartialEq for BlsPkBytes<S> {
  fn eq(&self, other: &Self) -> bool {
    self.inner == other.inner
  }
}

impl<S: BlsSchemeId> Hash for BlsPkBytes<S> {
  fn hash<H: Hasher>(&self, state: &mut H) {
    self.inner.hash(state);
  }
}

impl<S: BlsSchemeId> AsRef<[u8]> for BlsPkBytes<S> {
  fn as_ref(&self) -> &[u8] {
    &self.inner
  }
}

impl<S: BlsSchemeId> AsRef<[u8; BLS_PK_LEN]> for BlsPkBytes<S> {
  fn as_ref(&self) -> &[u8; BLS_PK_LEN] {
    &self.inner
  }
}

impl<S: BlsSchemeId> Default for BlsPkBytes<S> {
  fn default() -> Self {
    Self::from_bytes([0u8; BLS_PK_LEN])
  }
}

impl<S: BlsSchemeId> From<[u8; BLS_PK_LEN]> for BlsPkBytes<S> {
  fn from(bytes: [u8; BLS_PK_LEN]) -> Self {
    Self::from_bytes(bytes)
  }
}

impl<S: BlsSchemeId> From<BlsPkBytes<S>> for [u8; BLS_PK_LEN] {
  fn from(val: BlsPkBytes<S>) -> Self {
    val.inner
  }
}

impl<S: BlsSchemeId> TypeId for BlsPkBytes<S> {
  const TYPE_ID: u32 = S::PK_TYPE_ID;
}

impl<S: BlsSchemeId> BaseCodec for BlsPkBytes<S> {
  fn decode(data: &mut &[u8]) -> Result<Self, DecodeError> {
    take::<BLS_PK_LEN>(data).map(Self::from_bytes)
  }

  fn encode(&self, buf: &mut impl EncodeBuf) {
    buf.extend_from_slice(&self.inner);
  }
}

impl<S: BlsSchemeId> Encodable for BlsPkBytes<S> {
  type Encoder<'e> = VecEncoder;
  fn encoder(&self) -> Self::Encoder<'_> {
    let mut buf = Vec::new();
    BaseCodec::encode(self, &mut buf);
    VecEncoder::new(buf)
  }
}

impl<S: BlsSchemeId> Decodable for BlsPkBytes<S> {
  type Decoder = BufferDecoder<Self>;
  fn decoder() -> Self::Decoder {
    BufferDecoder::new(<Self as BaseCodec>::decode, MAX_SER_SIZE)
  }
}

impl<S: BlsSchemeId> Debug for BlsPkBytes<S> {
  fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
    write!(f, "BlsPkBytes<{}>(", S::LABEL)?;
    for byte in &self.inner {
      write!(f, "{byte:02x}")?;
    }
    write!(f, ")")
  }
}

impl<S: BlsSchemeId> Display for BlsPkBytes<S> {
  fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
    for byte in &self.inner {
      write!(f, "{byte:02x}")?;
    }
    Ok(())
  }
}

impl<S: BlsSchemeId> Hashable for BlsPkBytes<S> {
  type Hash = Hash160;

  fn hash(&self) -> Self::Hash {
    Self::Hash::from(*Ripemd160::hash(Sha256::hash(&self.inner).as_ref()).as_byte_array())
  }
}

impl<S: BlsSchemeId> Ord for BlsPkBytes<S> {
  fn cmp(&self, other: &Self) -> Ordering {
    self.inner.cmp(&other.inner)
  }
}

impl<S: BlsSchemeId> PartialOrd for BlsPkBytes<S> {
  fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
    Some(self.cmp(other))
  }
}

cfg_if! {
  if #[cfg(feature = "serde")] {
    use hex_conservative::{DisplayHex, FromHex};
    use serde::de::Error;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    impl<S: BlsSchemeId> Serialize for BlsPkBytes<S> {
      fn serialize<Z: Serializer>(&self, serializer: Z) -> Result<Z::Ok, Z::Error> {
        serializer.serialize_str(&self.inner.to_lower_hex_string())
      }
    }

    impl<'de, S: BlsSchemeId> Deserialize<'de> for BlsPkBytes<S> {
      fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = <String as Deserialize>::deserialize(deserializer)?;
        <[u8; BLS_PK_LEN] as FromHex>::from_hex(&s)
          .map(Self::from_bytes)
          .map_err(Error::custom)
      }
    }
  }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "test code")]
mod tests {
  use super::{BlsPkBytes, BLS_PK_LEN};
  use crate::bls::tests::PK_SAMPLE;
  use crate::bls::{BlsScChia, BlsScIetf};
  use crate::prelude::*;

  use dash_types::codec::TypeId;
  use rstest::rstest;

  #[rstest]
  fn roundtrip() {
    let pk = BlsPkBytes::<BlsScChia>::from_bytes(PK_SAMPLE);
    assert_eq!(*pk.as_bytes(), PK_SAMPLE);
    assert_eq!(pk.to_bytes(), PK_SAMPLE);
  }

  #[rstest]
  fn distinct_type_ids() {
    assert_ne!(BlsPkBytes::<BlsScChia>::TYPE_ID, BlsPkBytes::<BlsScIetf>::TYPE_ID,);
  }

  #[rstest]
  fn formatting() {
    let pk = BlsPkBytes::<BlsScIetf>::from_bytes(PK_SAMPLE);
    assert_eq!(format!("{pk}").len(), BLS_PK_LEN * 2);

    let pk = BlsPkBytes::<BlsScChia>::from_bytes(PK_SAMPLE);
    assert!(format!("{pk:?}").starts_with("BlsPkBytes<Chia>("));
  }

  #[rstest]
  fn null_check() {
    assert!(BlsPkBytes::<BlsScChia>::default().is_null());
    assert!(!BlsPkBytes::<BlsScChia>::from_bytes(PK_SAMPLE).is_null());
  }

  #[rstest]
  fn ordering() {
    let a = BlsPkBytes::<BlsScIetf>::from_bytes([0x01; BLS_PK_LEN]);
    let b = BlsPkBytes::<BlsScIetf>::from_bytes([0x02; BLS_PK_LEN]);
    assert!(a < b);
  }

  #[rstest]
  fn array_conversion() {
    let pk: BlsPkBytes<BlsScChia> = PK_SAMPLE.into();
    let array: [u8; BLS_PK_LEN] = pk.into();
    assert_eq!(array, PK_SAMPLE);
  }

  #[cfg(feature = "serde")]
  #[rstest]
  fn serde_roundtrip() {
    let pk = BlsPkBytes::<BlsScChia>::from_bytes(PK_SAMPLE);
    let json = serde_json::to_string(&pk).unwrap();
    assert_eq!(serde_json::from_str::<BlsPkBytes<BlsScChia>>(&json).unwrap(), pk);
  }
}
