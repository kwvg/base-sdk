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

impl LlmqType {
  /// DKG and signing parameters of the type, or `None` for
  /// [`LlmqType::LlmqNone`] and unknown types. Test and devnet types carry
  /// their default values, which a node may override on its command line.
  pub const fn params(self) -> Option<LlmqParams> {
    Some(match self {
      Self::Llmq50_60 => LLMQ_50_60,
      Self::Llmq400_60 => LLMQ_400_60,
      Self::Llmq400_85 => LLMQ_400_85,
      Self::Llmq100_67 => LLMQ_100_67,
      Self::Llmq60_75 => LLMQ_60_75,
      Self::Llmq25_67 => LLMQ_25_67,
      Self::LlmqTest | Self::LlmqTestV17 | Self::LlmqTestInstantsend => LLMQ_TEST,
      Self::LlmqTestPlatform => LLMQ_TEST_PLATFORM,
      Self::LlmqTestDip0024 => LLMQ_TEST_DIP0024,
      Self::LlmqDevnet => LLMQ_DEVNET,
      Self::LlmqDevnetDip0024 => LLMQ_DEVNET_DIP0024,
      Self::LlmqDevnetPlatform => LLMQ_DEVNET_PLATFORM,
      Self::LlmqNone | Self::Unknown(_) => return None,
    })
  }
}

/// DKG and signing parameters of an [`LlmqType`].
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Unencodable)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub struct LlmqParams {
  /// Whether quorums of the type rotate their members under DIP-0024.
  pub use_rotation: bool,
  /// Number of members.
  pub size: u16,
  /// Fewest valid members and signers a commitment may carry.
  pub min_size: u16,
  /// Number of signature shares that recover the quorum signature.
  pub threshold: u16,
  /// Blocks between the starts of two DKG sessions.
  pub dkg_interval: u16,
  /// Blocks per DKG phase.
  pub dkg_phase_blocks: u16,
  /// First block of the interval that must carry a commitment, inclusive.
  pub dkg_mining_window_start: u16,
  /// Last block of the interval that may carry a commitment, inclusive.
  pub dkg_mining_window_end: u16,
  /// Complaints that mark a member bad for every other member.
  pub dkg_bad_votes_threshold: u16,
  /// Number of recent quorums that take part in signing.
  pub signing_active_quorum_count: u16,
  /// Number of quorums whose intra-quorum connections a member keeps.
  pub keep_old_connections: u16,
  /// Number of quorums whose secret key shares a member keeps.
  pub keep_old_keys: u16,
  /// Members a signer sends its signature shares to before giving up.
  pub recovery_members: u16,
}

const LLMQ_50_60: LlmqParams = LlmqParams {
  use_rotation: false,
  size: 50,
  min_size: 40,
  threshold: 30,
  dkg_interval: 24,
  dkg_phase_blocks: 2,
  dkg_mining_window_start: 10,
  dkg_mining_window_end: 18,
  dkg_bad_votes_threshold: 40,
  signing_active_quorum_count: 24,
  keep_old_connections: 25,
  keep_old_keys: 48,
  recovery_members: 25,
};

const LLMQ_400_60: LlmqParams = LlmqParams {
  use_rotation: false,
  size: 400,
  min_size: 300,
  threshold: 240,
  dkg_interval: 288,
  dkg_phase_blocks: 4,
  dkg_mining_window_start: 20,
  dkg_mining_window_end: 28,
  dkg_bad_votes_threshold: 300,
  signing_active_quorum_count: 4,
  keep_old_connections: 5,
  keep_old_keys: 8,
  recovery_members: 100,
};

const LLMQ_400_85: LlmqParams = LlmqParams {
  use_rotation: false,
  size: 400,
  min_size: 350,
  threshold: 340,
  dkg_interval: 576,
  dkg_phase_blocks: 4,
  dkg_mining_window_start: 20,
  dkg_mining_window_end: 48,
  dkg_bad_votes_threshold: 300,
  signing_active_quorum_count: 4,
  keep_old_connections: 5,
  keep_old_keys: 8,
  recovery_members: 100,
};

const LLMQ_100_67: LlmqParams = LlmqParams {
  use_rotation: false,
  size: 100,
  min_size: 80,
  threshold: 67,
  dkg_interval: 24,
  dkg_phase_blocks: 2,
  dkg_mining_window_start: 10,
  dkg_mining_window_end: 18,
  dkg_bad_votes_threshold: 80,
  signing_active_quorum_count: 24,
  keep_old_connections: 25,
  keep_old_keys: 1440,
  recovery_members: 50,
};

const LLMQ_60_75: LlmqParams = LlmqParams {
  use_rotation: true,
  size: 60,
  min_size: 50,
  threshold: 45,
  dkg_interval: 288,
  dkg_phase_blocks: 2,
  dkg_mining_window_start: 42,
  dkg_mining_window_end: 50,
  dkg_bad_votes_threshold: 48,
  signing_active_quorum_count: 32,
  keep_old_connections: 64,
  keep_old_keys: 64,
  recovery_members: 25,
};

const LLMQ_25_67: LlmqParams = LlmqParams {
  use_rotation: false,
  size: 25,
  min_size: 22,
  threshold: 17,
  dkg_interval: 24,
  dkg_phase_blocks: 2,
  dkg_mining_window_start: 10,
  dkg_mining_window_end: 18,
  dkg_bad_votes_threshold: 22,
  signing_active_quorum_count: 24,
  keep_old_connections: 25,
  keep_old_keys: 1440,
  recovery_members: 12,
};

const LLMQ_TEST: LlmqParams = LlmqParams {
  use_rotation: false,
  size: 3,
  min_size: 2,
  threshold: 2,
  dkg_interval: 24,
  dkg_phase_blocks: 2,
  dkg_mining_window_start: 10,
  dkg_mining_window_end: 18,
  dkg_bad_votes_threshold: 2,
  signing_active_quorum_count: 2,
  keep_old_connections: 3,
  keep_old_keys: 4,
  recovery_members: 3,
};

const LLMQ_TEST_PLATFORM: LlmqParams = LlmqParams {
  use_rotation: false,
  size: 3,
  min_size: 2,
  threshold: 2,
  dkg_interval: 24,
  dkg_phase_blocks: 2,
  dkg_mining_window_start: 10,
  dkg_mining_window_end: 18,
  dkg_bad_votes_threshold: 2,
  signing_active_quorum_count: 2,
  keep_old_connections: 4,
  keep_old_keys: 1440,
  recovery_members: 3,
};

const LLMQ_TEST_DIP0024: LlmqParams = LlmqParams {
  use_rotation: true,
  size: 4,
  min_size: 4,
  threshold: 3,
  dkg_interval: 24,
  dkg_phase_blocks: 2,
  dkg_mining_window_start: 12,
  dkg_mining_window_end: 20,
  dkg_bad_votes_threshold: 2,
  signing_active_quorum_count: 2,
  keep_old_connections: 4,
  keep_old_keys: 4,
  recovery_members: 3,
};

const LLMQ_DEVNET: LlmqParams = LlmqParams {
  use_rotation: false,
  size: 12,
  min_size: 7,
  threshold: 6,
  dkg_interval: 24,
  dkg_phase_blocks: 2,
  dkg_mining_window_start: 10,
  dkg_mining_window_end: 18,
  dkg_bad_votes_threshold: 7,
  signing_active_quorum_count: 4,
  keep_old_connections: 5,
  keep_old_keys: 8,
  recovery_members: 6,
};

const LLMQ_DEVNET_DIP0024: LlmqParams = LlmqParams {
  use_rotation: true,
  size: 8,
  min_size: 6,
  threshold: 4,
  dkg_interval: 48,
  dkg_phase_blocks: 2,
  dkg_mining_window_start: 12,
  dkg_mining_window_end: 20,
  dkg_bad_votes_threshold: 7,
  signing_active_quorum_count: 2,
  keep_old_connections: 4,
  keep_old_keys: 4,
  recovery_members: 4,
};

const LLMQ_DEVNET_PLATFORM: LlmqParams = LlmqParams {
  use_rotation: false,
  size: 12,
  min_size: 9,
  threshold: 8,
  dkg_interval: 24,
  dkg_phase_blocks: 2,
  dkg_mining_window_start: 10,
  dkg_mining_window_end: 18,
  dkg_bad_votes_threshold: 7,
  signing_active_quorum_count: 4,
  keep_old_connections: 5,
  keep_old_keys: 1440,
  recovery_members: 6,
};

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
  use super::{DynBitset, LlmqParams, LlmqType, RevocationReason};
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
  #[case::llmq_50_60(LlmqType::Llmq50_60, false, [50, 40, 30], [24, 2, 10, 18, 40], [24, 25, 48, 25])]
  #[case::llmq_400_60(LlmqType::Llmq400_60, false, [400, 300, 240], [288, 4, 20, 28, 300], [4, 5, 8, 100])]
  #[case::llmq_400_85(LlmqType::Llmq400_85, false, [400, 350, 340], [576, 4, 20, 48, 300], [4, 5, 8, 100])]
  #[case::llmq_100_67(LlmqType::Llmq100_67, false, [100, 80, 67], [24, 2, 10, 18, 80], [24, 25, 1440, 50])]
  #[case::llmq_60_75(LlmqType::Llmq60_75, true, [60, 50, 45], [288, 2, 42, 50, 48], [32, 64, 64, 25])]
  #[case::llmq_25_67(LlmqType::Llmq25_67, false, [25, 22, 17], [24, 2, 10, 18, 22], [24, 25, 1440, 12])]
  #[case::llmq_test(LlmqType::LlmqTest, false, [3, 2, 2], [24, 2, 10, 18, 2], [2, 3, 4, 3])]
  #[case::llmq_test_v17(LlmqType::LlmqTestV17, false, [3, 2, 2], [24, 2, 10, 18, 2], [2, 3, 4, 3])]
  #[case::llmq_test_dip0024(LlmqType::LlmqTestDip0024, true, [4, 4, 3], [24, 2, 12, 20, 2], [2, 4, 4, 3])]
  #[case::llmq_test_instantsend(LlmqType::LlmqTestInstantsend, false, [3, 2, 2], [24, 2, 10, 18, 2], [2, 3, 4, 3])]
  #[case::llmq_test_platform(LlmqType::LlmqTestPlatform, false, [3, 2, 2], [24, 2, 10, 18, 2], [2, 4, 1440, 3])]
  #[case::llmq_devnet(LlmqType::LlmqDevnet, false, [12, 7, 6], [24, 2, 10, 18, 7], [4, 5, 8, 6])]
  #[case::llmq_devnet_dip0024(LlmqType::LlmqDevnetDip0024, true, [8, 6, 4], [48, 2, 12, 20, 7], [2, 4, 4, 4])]
  #[case::llmq_devnet_platform(LlmqType::LlmqDevnetPlatform, false, [12, 9, 8], [24, 2, 10, 18, 7], [4, 5, 1440, 6])]
  fn llmq_params_follow_the_reference_table(
    #[case] llmq_type: LlmqType,
    #[case] use_rotation: bool,
    #[case] sizes: [u16; 3],
    #[case] dkg: [u16; 5],
    #[case] signing: [u16; 4],
  ) {
    // Each array follows the field order of `LlmqParams`.
    let [size, min_size, threshold] = sizes;
    let [dkg_interval, dkg_phase_blocks, dkg_mining_window_start, dkg_mining_window_end, dkg_bad_votes_threshold] = dkg;
    let [signing_active_quorum_count, keep_old_connections, keep_old_keys, recovery_members] = signing;
    assert_eq!(
      llmq_type.params(),
      Some(LlmqParams {
        use_rotation,
        size,
        min_size,
        threshold,
        dkg_interval,
        dkg_phase_blocks,
        dkg_mining_window_start,
        dkg_mining_window_end,
        dkg_bad_votes_threshold,
        signing_active_quorum_count,
        keep_old_connections,
        keep_old_keys,
        recovery_members,
      })
    );
  }

  #[rstest]
  #[case::none(LlmqType::LlmqNone)]
  #[case::unknown(LlmqType::Unknown(7))]
  fn none_and_unknown_types_have_no_params(#[case] llmq_type: LlmqType) {
    assert_eq!(llmq_type.params(), None);
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
