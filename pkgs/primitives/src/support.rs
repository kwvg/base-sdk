//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Protocol support types for special transaction payloads.

use crate::hash_impl;
use crate::prelude::*;

use dash_types::codec::{self, BaseCodec, DecodeError, EncodeBuf, NumCodec};
use dash_types::{impl_num, impl_type, TypeId, Unencodable};

use core::fmt;

/// LLMQ type (quorum size/threshold configuration).
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, TypeId)]
pub enum LlmqType {
  /// 50 members, 60% threshold.
  Llmq50_60,
  /// 400 members, 60% threshold.
  Llmq400_60,
  /// 400 members, 85% threshold.
  Llmq400_85,
  /// 100 members, 67% threshold.
  Llmq100_67,
  /// 60 members, 75% threshold.
  Llmq60_75,
  /// 25 members, 67% threshold.
  Llmq25_67,
  /// Regtest quorum.
  LlmqTest,
  /// Devnet quorum.
  LlmqDevnet,
  /// Test v17-era quorum.
  LlmqTestV17,
  /// Test InstantSend quorum.
  LlmqTestInstantsend,
  /// Test Platform quorum.
  LlmqTestPlatform,
  /// Devnet Platform quorum.
  LlmqDevnetPlatform,
  /// Unrecognized type code.
  Unknown(u8),
}

impl NumCodec<u8> for LlmqType {
  fn from_base(val: u8) -> Self {
    match val {
      1 => Self::Llmq50_60,
      2 => Self::Llmq400_60,
      3 => Self::Llmq400_85,
      4 => Self::Llmq100_67,
      5 => Self::Llmq60_75,
      6 => Self::Llmq25_67,
      100 => Self::LlmqTest,
      101 => Self::LlmqDevnet,
      102 => Self::LlmqTestV17,
      104 => Self::LlmqTestInstantsend,
      106 => Self::LlmqTestPlatform,
      107 => Self::LlmqDevnetPlatform,
      other => Self::Unknown(other),
    }
  }

  fn to_base(&self) -> u8 {
    match self {
      Self::Llmq50_60 => 1,
      Self::Llmq400_60 => 2,
      Self::Llmq400_85 => 3,
      Self::Llmq100_67 => 4,
      Self::Llmq60_75 => 5,
      Self::Llmq25_67 => 6,
      Self::LlmqTest => 100,
      Self::LlmqDevnet => 101,
      Self::LlmqTestV17 => 102,
      Self::LlmqTestInstantsend => 104,
      Self::LlmqTestPlatform => 106,
      Self::LlmqDevnetPlatform => 107,
      Self::Unknown(v) => *v,
    }
  }
}

impl_num!(LlmqType, u8);

hash_impl!(LlmqType);

impl fmt::Display for LlmqType {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    match self {
      Self::Llmq50_60 => write!(f, "llmq_50_60"),
      Self::Llmq400_60 => write!(f, "llmq_400_60"),
      Self::Llmq400_85 => write!(f, "llmq_400_85"),
      Self::Llmq100_67 => write!(f, "llmq_100_67"),
      Self::Llmq60_75 => write!(f, "llmq_60_75"),
      Self::Llmq25_67 => write!(f, "llmq_25_67"),
      Self::LlmqTest => write!(f, "llmq_test"),
      Self::LlmqDevnet => write!(f, "llmq_devnet"),
      Self::LlmqTestV17 => write!(f, "llmq_test_v17"),
      Self::LlmqTestInstantsend => write!(f, "llmq_test_instantsend"),
      Self::LlmqTestPlatform => write!(f, "llmq_test_platform"),
      Self::LlmqDevnetPlatform => write!(f, "llmq_devnet_platform"),
      Self::Unknown(v) => write!(f, "unknown({v})"),
    }
  }
}

/// Revocation reason for provider update revocation.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, TypeId)]
pub enum RevocationReason {
  /// No specific reason.
  NotSpecified,
  /// Key material has been compromised.
  KeyCompromise,
  /// Operator is changing keys.
  ChangeOfKeys,
  /// Service level violation.
  ViolationOfService,
  /// Unknown reason code.
  Unknown(u16),
}

impl NumCodec<u16> for RevocationReason {
  fn from_base(val: u16) -> Self {
    match val {
      0 => Self::NotSpecified,
      1 => Self::KeyCompromise,
      2 => Self::ChangeOfKeys,
      3 => Self::ViolationOfService,
      other => Self::Unknown(other),
    }
  }

  fn to_base(&self) -> u16 {
    match self {
      Self::NotSpecified => 0,
      Self::KeyCompromise => 1,
      Self::ChangeOfKeys => 2,
      Self::ViolationOfService => 3,
      Self::Unknown(v) => *v,
    }
  }
}

impl_num!(RevocationReason, u16);

hash_impl!(RevocationReason);

impl fmt::Display for RevocationReason {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    match self {
      Self::NotSpecified => write!(f, "not_specified"),
      Self::KeyCompromise => write!(f, "key_compromise"),
      Self::ChangeOfKeys => write!(f, "change_of_keys"),
      Self::ViolationOfService => write!(f, "violation_of_service"),
      Self::Unknown(v) => write!(f, "unknown({v})"),
    }
  }
}

/// LSB-first dynamic bitset.
#[derive(Clone, Debug, Eq, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde", serde(into = "DynBitsetSerde"))]
pub struct DynBitset {
  /// Number of bits in the bitset.
  pub num_bits: u64,
  /// Raw byte data (LSB-first encoding).
  pub data: Vec<u8>,
}

impl_type!(DynBitset);

/// Serde helper for [`DynBitset`] that validates on deserialisation.
#[cfg(feature = "serde")]
#[derive(Clone, Debug, Eq, Hash, PartialEq, Unencodable, ::serde::Serialize, ::serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct DynBitsetSerde {
  num_bits: u64,
  #[serde(with = "dash_types::serialize::hex")]
  data: Vec<u8>,
}

impl BaseCodec for DynBitset {
  fn decode(data: &mut &[u8]) -> Result<Self, DecodeError> {
    let num_bits = codec::read_compact_u64(data)?;
    let byte_len = usize::try_from(num_bits.div_ceil(8)).map_err(|_| DecodeError::CompactSizeExceedsLimit {
      limit: usize::MAX,
      value: num_bits,
    })?;
    let raw = codec::read_bytes(data, byte_len)?;
    let remainder = (num_bits % 8) as u32;
    if remainder != 0 {
      let mask = !((1u8 << remainder) - 1);
      if raw[byte_len - 1] & mask != 0 {
        return Err(DecodeError::InvalidValue {
          expected: vec![0],
          actual: u64::from(raw[byte_len - 1] & mask),
        });
      }
    }
    Ok(Self {
      num_bits,
      data: raw.to_vec(),
    })
  }

  fn encode(&self, buf: &mut impl EncodeBuf) {
    codec::write_compact_u64(self.num_bits, buf);
    let required = (self.num_bits as usize).div_ceil(8);
    let src = &self.data;
    let take = src.len().min(required);
    if take > 0 {
      // nosemgrep: codec-no-raw-extend
      buf.extend_from_slice(&src[..take - 1]);
      // Mask padding bits only when the last source byte is
      // also the final output byte (take == required).
      let last_byte = if take == required {
        let remainder = (self.num_bits % 8) as u32;
        if remainder != 0 {
          src[take - 1] & ((1u8 << remainder) - 1)
        } else {
          src[take - 1]
        }
      } else {
        src[take - 1]
      };
      buf.push(last_byte);
    }
    // Pad with zero bytes if data is shorter than required.
    for _ in take..required {
      buf.push(0);
    }
  }
}

hash_impl!(DynBitset);

impl DynBitset {
  /// Returns the bit at the given index.
  pub fn get(&self, index: u64) -> Option<bool> {
    if index >= self.num_bits {
      return None;
    }
    let byte_idx = (index / 8) as usize;
    let bit_idx = (index % 8) as u32;
    self.data.get(byte_idx).map(|b| (b >> bit_idx) & 1 == 1)
  }

  /// Counts the number of set bits (respects [`num_bits`](Self::num_bits)).
  pub fn count_ones(&self) -> u64 {
    let byte_len = (self.num_bits as usize).div_ceil(8);
    let relevant = &self.data[..byte_len.min(self.data.len())];
    let remainder = (self.num_bits % 8) as u32;
    if remainder == 0 || relevant.is_empty() {
      return relevant.iter().map(|b| u64::from(b.count_ones())).sum();
    }
    let (full, last) = relevant.split_at(relevant.len() - 1);
    let mask = (1u8 << remainder) - 1;
    full.iter().map(|b| u64::from(b.count_ones())).sum::<u64>() + u64::from((last[0] & mask).count_ones())
  }

  /// Iterates over indices of set bits.
  pub fn iter_set_bits(&self) -> DynBitsetIterator<'_> {
    DynBitsetIterator { bitset: self, index: 0 }
  }
}

#[cfg(feature = "serde")]
impl From<DynBitset> for DynBitsetSerde {
  fn from(b: DynBitset) -> Self {
    Self {
      num_bits: b.num_bits,
      data: b.data,
    }
  }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for DynBitset {
  fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
    let raw = DynBitsetSerde::deserialize(deserializer)?;
    let num_bits: usize = raw
      .num_bits
      .try_into()
      .map_err(|_| serde::de::Error::custom("DynBitset num_bits too large"))?;
    let required = num_bits.div_ceil(8);
    if raw.data.len() != required {
      return Err(serde::de::Error::custom(format!(
        "DynBitset data length mismatch: {0} bytes for {1} bits (expected {2})",
        raw.data.len(),
        raw.num_bits,
        required,
      )));
    }
    let remainder = num_bits % 8;
    if remainder != 0 {
      let mask = !((1u8 << remainder) - 1);
      if raw.data[required - 1] & mask != 0 {
        return Err(serde::de::Error::custom(format!(
          "DynBitset padding bits set in last byte: {:#04x} for {1} bits",
          raw.data[required - 1],
          raw.num_bits,
        )));
      }
    }
    Ok(Self {
      num_bits: raw.num_bits,
      data: raw.data,
    })
  }
}

/// Iterator over set bit indices in a [`DynBitset`].
#[derive(Clone, Debug, Unencodable)]
pub struct DynBitsetIterator<'a> {
  bitset: &'a DynBitset,
  index: u64,
}

impl Iterator for DynBitsetIterator<'_> {
  type Item = u64;

  fn next(&mut self) -> Option<Self::Item> {
    while self.index < self.bitset.num_bits {
      let idx = self.index;
      self.index += 1;
      if self.bitset.get(idx) == Some(true) {
        return Some(idx);
      }
    }
    None
  }
}
