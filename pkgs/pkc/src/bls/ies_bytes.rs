//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Byte bag types for BLS-IES encrypted blobs.

use crate::bls::BLS_PK_LEN;
use crate::prelude::*;

use bitcoin_consensus_encoding::{Decodable, Encodable};
use dash_types::codec::{read_bytes, read_compact_size, write_compact_size, BaseCodec, DecodeError, EncodeBuf};
use dash_types::{BufferDecoder, VecEncoder};

use core::fmt;

/// IV seed length for BLS-IES encryption.
pub const BLS_IES_IV_LEN: usize = 32;

/// Unvalidated BLS-IES encrypted blob bytes.
///
/// Serialization layout matches Dash Core:
/// `[ephemeral_pk_48][iv_seed_32][compact_size_len][data...]`.
#[derive(Clone, Eq, PartialEq)]
pub struct BlsIesBytes {
  ephemeral_pk: [u8; BLS_PK_LEN],
  iv_seed: [u8; BLS_IES_IV_LEN],
  data: Vec<u8>,
}

impl BlsIesBytes {
  /// Constructs from raw components.
  pub fn new(ephemeral_pk: [u8; BLS_PK_LEN], iv_seed: [u8; BLS_IES_IV_LEN], data: Vec<u8>) -> Self {
    Self {
      ephemeral_pk,
      iv_seed,
      data,
    }
  }

  /// Borrows the ephemeral public key bytes.
  pub fn ephemeral_pk(&self) -> &[u8; BLS_PK_LEN] {
    &self.ephemeral_pk
  }

  /// Borrows the IV seed.
  pub fn iv_seed(&self) -> &[u8; BLS_IES_IV_LEN] {
    &self.iv_seed
  }

  /// Borrows the ciphertext data.
  pub fn data(&self) -> &[u8] {
    &self.data
  }
}

impl fmt::Debug for BlsIesBytes {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.debug_struct("BlsIesBytes")
      .field(
        "ephemeral_pk",
        &hex_conservative::DisplayHex::as_hex(&self.ephemeral_pk[..]),
      )
      .field("iv_seed", &hex_conservative::DisplayHex::as_hex(&self.iv_seed))
      .field("data_len", &self.data.len())
      .finish()
  }
}

impl BaseCodec for BlsIesBytes {
  fn decode(data: &mut &[u8]) -> Result<Self, DecodeError> {
    let pk = <[u8; BLS_PK_LEN]>::decode(data)?;
    let iv = <[u8; BLS_IES_IV_LEN]>::decode(data)?;
    let len = read_compact_size(data, data.len())?;
    let ct = read_bytes(data, len)?;
    Ok(Self {
      ephemeral_pk: pk,
      iv_seed: iv,
      data: ct.to_vec(),
    })
  }

  fn encode(&self, buf: &mut impl EncodeBuf) {
    buf.extend_from_slice(&self.ephemeral_pk);
    buf.extend_from_slice(&self.iv_seed);
    write_compact_size(self.data.len(), buf);
    buf.extend_from_slice(&self.data);
  }
}

impl Encodable for BlsIesBytes {
  type Encoder<'e> = VecEncoder;
  fn encoder(&self) -> Self::Encoder<'_> {
    let mut buf = Vec::new();
    BaseCodec::encode(self, &mut buf);
    VecEncoder::new(buf)
  }
}

impl Decodable for BlsIesBytes {
  type Decoder = BufferDecoder<Self>;
  fn decoder() -> Self::Decoder {
    BufferDecoder::new(<Self as BaseCodec>::decode, dash_types::MAX_SER_SIZE)
  }
}

/// Unvalidated BLS-IES multi-recipient encrypted blob.
///
/// Serialization layout:
/// `[ephemeral_pk_48][iv_seed_32][compact_count][compact_len_0][data_0]...`.
#[derive(Clone, Eq, PartialEq)]
pub struct BlsIesMultiBytes {
  ephemeral_pk: [u8; BLS_PK_LEN],
  iv_seed: [u8; BLS_IES_IV_LEN],
  blobs: Vec<Vec<u8>>,
}

impl BlsIesMultiBytes {
  /// Constructs from raw components.
  pub fn new(ephemeral_pk: [u8; BLS_PK_LEN], iv_seed: [u8; BLS_IES_IV_LEN], blobs: Vec<Vec<u8>>) -> Self {
    Self {
      ephemeral_pk,
      iv_seed,
      blobs,
    }
  }

  /// Borrows the ephemeral public key bytes.
  pub fn ephemeral_pk(&self) -> &[u8; BLS_PK_LEN] {
    &self.ephemeral_pk
  }

  /// Borrows the IV seed.
  pub fn iv_seed(&self) -> &[u8; BLS_IES_IV_LEN] {
    &self.iv_seed
  }

  /// Borrows the per-recipient ciphertext blobs.
  pub fn blobs(&self) -> &[Vec<u8>] {
    &self.blobs
  }
}

impl fmt::Debug for BlsIesMultiBytes {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.debug_struct("BlsIesMultiBytes")
      .field(
        "ephemeral_pk",
        &hex_conservative::DisplayHex::as_hex(&self.ephemeral_pk[..]),
      )
      .field("iv_seed", &hex_conservative::DisplayHex::as_hex(&self.iv_seed))
      .field("blob_count", &self.blobs.len())
      .finish()
  }
}

impl BaseCodec for BlsIesMultiBytes {
  fn decode(data: &mut &[u8]) -> Result<Self, DecodeError> {
    let pk = <[u8; BLS_PK_LEN]>::decode(data)?;
    let iv = <[u8; BLS_IES_IV_LEN]>::decode(data)?;
    let count = read_compact_size(data, data.len())?;
    let mut blobs = Vec::with_capacity(count.min(256));
    for _ in 0..count {
      let len = read_compact_size(data, data.len())?;
      let ct = read_bytes(data, len)?;
      blobs.push(ct.to_vec());
    }
    Ok(Self {
      ephemeral_pk: pk,
      iv_seed: iv,
      blobs,
    })
  }

  fn encode(&self, buf: &mut impl EncodeBuf) {
    buf.extend_from_slice(&self.ephemeral_pk);
    buf.extend_from_slice(&self.iv_seed);
    write_compact_size(self.blobs.len(), buf);
    for blob in &self.blobs {
      write_compact_size(blob.len(), buf);
      buf.extend_from_slice(blob);
    }
  }
}

impl Encodable for BlsIesMultiBytes {
  type Encoder<'e> = VecEncoder;
  fn encoder(&self) -> Self::Encoder<'_> {
    let mut buf = Vec::new();
    BaseCodec::encode(self, &mut buf);
    VecEncoder::new(buf)
  }
}

impl Decodable for BlsIesMultiBytes {
  type Decoder = BufferDecoder<Self>;
  fn decoder() -> Self::Decoder {
    BufferDecoder::new(<Self as BaseCodec>::decode, dash_types::MAX_SER_SIZE)
  }
}

cfg_if::cfg_if! {
  if #[cfg(feature = "serde")] {
    use hex_conservative::{DisplayHex, FromHex};
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use serde::de::Error;

    impl Serialize for BlsIesBytes {
      fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut buf = Vec::new();
        BaseCodec::encode(self, &mut buf);
        serializer.serialize_str(&buf.to_lower_hex_string())
      }
    }

    impl<'de> Deserialize<'de> for BlsIesBytes {
      fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = <String as Deserialize>::deserialize(deserializer)?;
        let bytes = <Vec<u8> as FromHex>::from_hex(&s).map_err(Error::custom)?;
        let mut slice = bytes.as_slice();
        BaseCodec::decode(&mut slice).map_err(Error::custom)
      }
    }

    impl Serialize for BlsIesMultiBytes {
      fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut buf = Vec::new();
        BaseCodec::encode(self, &mut buf);
        serializer.serialize_str(&buf.to_lower_hex_string())
      }
    }

    impl<'de> Deserialize<'de> for BlsIesMultiBytes {
      fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = <String as Deserialize>::deserialize(deserializer)?;
        let bytes = <Vec<u8> as FromHex>::from_hex(&s).map_err(Error::custom)?;
        let mut slice = bytes.as_slice();
        BaseCodec::decode(&mut slice).map_err(Error::custom)
      }
    }
  }
}
