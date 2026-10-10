//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Protocol support types for special transaction payloads.

use crate::hash_impl;
use crate::prelude::*;

use dash_types::codec::{self, BaseCodec, DecodeError, EncodeBuf};
use dash_types::type_id::{TypeId, Unencodable};
use dash_types::{enum_map, impl_num, impl_type, CompactSize, Numeric};

enum_map! {
  /// LLMQ type (quorum size/threshold configuration).
  #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, TypeId)]
  pub enum LlmqType, u8, Unknown {
    /// 50 members, 60% threshold.
    Llmq50_60 = 1 => "llmq_50_60",
    /// 400 members, 60% threshold.
    Llmq400_60 = 2 => "llmq_400_60",
    /// 400 members, 85% threshold.
    Llmq400_85 = 3 => "llmq_400_85",
    /// 100 members, 67% threshold.
    Llmq100_67 = 4 => "llmq_100_67",
    /// 60 members, 75% threshold.
    Llmq60_75 = 5 => "llmq_60_75",
    /// 25 members, 67% threshold.
    Llmq25_67 = 6 => "llmq_25_67",
    /// Regtest quorum.
    LlmqTest = 100 => "llmq_test",
    /// Devnet quorum.
    LlmqDevnet = 101 => "llmq_devnet",
    /// Test v17-era quorum.
    LlmqTestV17 = 102 => "llmq_test_v17",
    /// Test rotated (DIP-0024) quorum.
    LlmqTestDip0024 = 103 => "llmq_test_dip0024",
    /// Test InstantSend quorum.
    LlmqTestInstantsend = 104 => "llmq_test_instantsend",
    /// Devnet rotated (DIP-0024) quorum.
    LlmqDevnetDip0024 = 105 => "llmq_devnet_dip0024",
    /// Test Platform quorum.
    LlmqTestPlatform = 106 => "llmq_test_platform",
    /// Devnet Platform quorum.
    LlmqDevnetPlatform = 107 => "llmq_devnet_platform",
    /// No quorum type.
    LlmqNone = 0xff => "llmq_none",
  }
}

impl_num!(LlmqType, u8);

hash_impl!(LlmqType);

enum_map! {
  /// Revocation reason for provider update revocation.
  #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, TypeId)]
  pub enum RevocationReason, u16, Unknown {
    /// No specific reason.
    NotSpecified = 0 => "not_specified",
    /// The operator terminates the service.
    TerminationOfService = 1 => "termination_of_service",
    /// The operator keys are compromised.
    CompromisedKeys = 2 => "compromised_keys",
    /// The operator is changing keys.
    ChangeOfKeys = 3 => "change_of_keys",
  }
}

impl_num!(RevocationReason, u16);

hash_impl!(RevocationReason);

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
    let num_bits = CompactSize::decode_checked(data)?.to_base();
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
    CompactSize::from(self.num_bits).encode(buf);
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

#[cfg(test)]
mod tests {
  use super::{DynBitset, LlmqType, RevocationReason};
  use crate::prelude::*;

  use dash_types::codec::{BaseCodec, DecodeError};
  use dash_types::{CompactSize, Numeric, MAX_SIZE};
  use rstest::rstest;

  fn prefixed(num_bits: u64, rest: &[u8]) -> Vec<u8> {
    let mut wire = Vec::new();
    CompactSize::new(num_bits).encode(&mut wire);
    for &byte in rest {
      byte.encode(&mut wire);
    }
    wire
  }

  #[rstest]
  fn bit_count_past_max_size_exceeds_the_limit() {
    assert_eq!(
      DynBitset::decode(&mut prefixed(MAX_SIZE + 1, &[0xFF]).as_slice()),
      Err(DecodeError::CompactSizeExceedsLimit {
        limit: MAX_SIZE as usize,
        value: MAX_SIZE + 1,
      })
    );
  }

  #[rstest]
  fn bit_count_at_max_size_reaches_the_input_bound() {
    assert!(matches!(
      DynBitset::decode(&mut prefixed(MAX_SIZE, &[0xFF]).as_slice()),
      Err(DecodeError::Eof { .. })
    ));
  }

  #[rstest]
  #[case::exact(8, &[0xA5], true)]
  #[case::padding_clear(3, &[0x05], true)]
  #[case::padding_set(3, &[0x0D], false)]
  fn padding_bits_must_be_clear(#[case] num_bits: u64, #[case] rest: &[u8], #[case] ok: bool) {
    let wire = prefixed(num_bits, rest);
    assert_eq!(DynBitset::decode(&mut wire.as_slice()).is_ok(), ok);
  }

  #[rstest]
  #[case::llmq_50_60(1, LlmqType::Llmq50_60)]
  #[case::llmq_400_60(2, LlmqType::Llmq400_60)]
  #[case::llmq_400_85(3, LlmqType::Llmq400_85)]
  #[case::llmq_100_67(4, LlmqType::Llmq100_67)]
  #[case::llmq_60_75(5, LlmqType::Llmq60_75)]
  #[case::llmq_25_67(6, LlmqType::Llmq25_67)]
  #[case::llmq_test(100, LlmqType::LlmqTest)]
  #[case::llmq_devnet(101, LlmqType::LlmqDevnet)]
  #[case::llmq_test_v17(102, LlmqType::LlmqTestV17)]
  #[case::llmq_test_dip0024(103, LlmqType::LlmqTestDip0024)]
  #[case::llmq_test_instantsend(104, LlmqType::LlmqTestInstantsend)]
  #[case::llmq_devnet_dip0024(105, LlmqType::LlmqDevnetDip0024)]
  #[case::llmq_test_platform(106, LlmqType::LlmqTestPlatform)]
  #[case::llmq_devnet_platform(107, LlmqType::LlmqDevnetPlatform)]
  #[case::llmq_none(0xff, LlmqType::LlmqNone)]
  fn llmq_types_follow_the_reference_codes(#[case] code: u8, #[case] llmq_type: LlmqType) {
    assert_eq!(LlmqType::from_base(code), llmq_type);
    assert_eq!(llmq_type.to_base(), code);
  }

  #[rstest]
  #[case::zero(0)]
  #[case::between_mainnet_and_test(7)]
  #[case::past_devnet_platform(108)]
  fn other_llmq_codes_are_unknown(#[case] code: u8) {
    assert_eq!(LlmqType::from_base(code), LlmqType::Unknown(code));
  }

  #[rstest]
  #[case::not_specified(0, RevocationReason::NotSpecified, "not_specified")]
  #[case::termination_of_service(1, RevocationReason::TerminationOfService, "termination_of_service")]
  #[case::compromised_keys(2, RevocationReason::CompromisedKeys, "compromised_keys")]
  #[case::change_of_keys(3, RevocationReason::ChangeOfKeys, "change_of_keys")]
  fn revocation_reasons_follow_the_reference_codes(
    #[case] code: u16,
    #[case] reason: RevocationReason,
    #[case] label: &str,
  ) {
    assert_eq!(RevocationReason::from_base(code), reason);
    assert_eq!(reason.to_string(), label);
  }

  #[rstest]
  fn codes_past_change_of_keys_are_unknown() {
    assert_eq!(RevocationReason::from_base(4), RevocationReason::Unknown(4));
  }
}
