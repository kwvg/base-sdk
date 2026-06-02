//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Protocol support types for special transaction payloads.

use crate::prelude::*;

use bitcoin_consensus_encoding as encoding;
use bitcoin_internals::array::ArrayExt as _;

use core::fmt;

/// LLMQ type (quorum size/threshold configuration).
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
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

impl LlmqType {
  /// Converts a raw byte to an `LlmqType`.
  pub const fn from_u8(val: u8) -> Self {
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

  /// Converts to raw byte value.
  pub const fn to_u8(self) -> u8 {
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
      Self::Unknown(v) => v,
    }
  }
}

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
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
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

impl RevocationReason {
  /// Converts a raw `u16`.
  pub const fn from_u16(val: u16) -> Self {
    match val {
      0 => Self::NotSpecified,
      1 => Self::KeyCompromise,
      2 => Self::ChangeOfKeys,
      3 => Self::ViolationOfService,
      other => Self::Unknown(other),
    }
  }

  /// Converts to raw `u16`.
  pub const fn to_u16(self) -> u16 {
    match self {
      Self::NotSpecified => 0,
      Self::KeyCompromise => 1,
      Self::ChangeOfKeys => 2,
      Self::ViolationOfService => 3,
      Self::Unknown(v) => v,
    }
  }
}

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

/// Network address type (BIP155).
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum NetworkType {
  /// IPv4.
  Ipv4,
  /// IPv6.
  Ipv6,
  /// Tor v3 hidden service.
  TorV3,
  /// I2P.
  I2P,
  /// CJDNS.
  Cjdns,
  /// Unknown network type.
  Unknown(u8),
}

impl NetworkType {
  /// Converts a raw byte.
  pub const fn from_u8(val: u8) -> Self {
    match val {
      1 => Self::Ipv4,
      2 => Self::Ipv6,
      4 => Self::TorV3,
      5 => Self::I2P,
      6 => Self::Cjdns,
      other => Self::Unknown(other),
    }
  }

  /// Converts to raw byte.
  pub const fn to_u8(self) -> u8 {
    match self {
      Self::Ipv4 => 1,
      Self::Ipv6 => 2,
      Self::TorV3 => 4,
      Self::I2P => 5,
      Self::Cjdns => 6,
      Self::Unknown(v) => v,
    }
  }
}

/// LSB-first dynamic bitset.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(feature = "serde", serde(into = "DynBitsetSerde"))]
pub struct DynBitset {
  /// Number of bits in the bitset.
  pub num_bits: u64,
  /// Raw byte data (LSB-first encoding).
  pub data: Vec<u8>,
}

/// Serde helper for [`DynBitset`] that validates on deserialisation.
#[cfg(feature = "serde")]
#[derive(Clone, Debug, Eq, Hash, PartialEq, serde::Serialize, serde::Deserialize)]
struct DynBitsetSerde {
  num_bits: u64,
  #[serde(with = "dash_types::serialize::hex")]
  data: Vec<u8>,
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

  /// Counts the number of set bits.
  pub fn count_ones(&self) -> u64 {
    self.data.iter().map(|b| u64::from(b.count_ones())).sum()
  }

  /// Iterates over indices of set bits.
  pub fn iter_set_bits(&self) -> DynBitsetIterator<'_> {
    DynBitsetIterator { bitset: self, index: 0 }
  }
}

/// Iterator over set bit indices in a [`DynBitset`].
#[derive(Clone, Debug)]
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

// Ecosystem encoding traits for DynBitset.

encoding::encoder_newtype! {
  /// Encoder for [`DynBitset`].
  pub struct DynBitsetEncoder<'e>(
    encoding::Encoder2<
      encoding::CompactSizeEncoder,
      encoding::BytesEncoder<'e>,
    >
  );
}

impl encoding::Encodable for DynBitset {
  type Encoder<'e> = DynBitsetEncoder<'e>;

  fn encoder(&self) -> Self::Encoder<'_> {
    DynBitsetEncoder::new(encoding::Encoder2::new(
      encoding::CompactSizeEncoder::new_u64(self.num_bits),
      encoding::BytesEncoder::without_length_prefix(&self.data),
    ))
  }
}

/// Legacy CService network address (ADDRv1 format, 18 bytes).
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct CService {
  /// 16-byte address (IPv4-mapped IPv6 or native IPv6).
  #[cfg_attr(feature = "serde", serde(with = "dash_types::serialize::hex::w16"))]
  pub addr: [u8; 16],
  /// Network port (big-endian on the wire).
  pub port: u16,
}

// Ecosystem encoding traits for CService.

encoding::encoder_newtype_exact! {
  /// Encoder for [`CService`].
  pub struct CServiceEncoder<'e>(
    encoding::Encoder2<encoding::BytesEncoder<'e>, encoding::ArrayEncoder<2>>
  );
}

impl encoding::Encodable for CService {
  type Encoder<'e> = CServiceEncoder<'e>;

  fn encoder(&self) -> Self::Encoder<'_> {
    CServiceEncoder::new(encoding::Encoder2::new(
      encoding::BytesEncoder::without_length_prefix(&self.addr),
      encoding::ArrayEncoder::without_length_prefix(self.port.to_be_bytes()),
    ))
  }
}

/// Decoder for [`CService`].
#[derive(Clone, Debug)]
pub struct CServiceDecoder(encoding::ArrayDecoder<18>);

impl CServiceDecoder {
  /// Constructs a new decoder.
  pub const fn new() -> Self {
    Self(encoding::ArrayDecoder::new())
  }
}

impl Default for CServiceDecoder {
  fn default() -> Self {
    Self::new()
  }
}

/// Decode error for [`CService`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CServiceDecoderError(encoding::UnexpectedEofError);

impl fmt::Display for CServiceDecoderError {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "cservice decode: {}", self.0)
  }
}

impl encoding::Decoder for CServiceDecoder {
  type Output = CService;
  type Error = CServiceDecoderError;

  #[inline]
  fn push_bytes(&mut self, bytes: &mut &[u8]) -> Result<bool, Self::Error> {
    self.0.push_bytes(bytes).map_err(CServiceDecoderError)
  }

  #[inline]
  fn end(self) -> Result<Self::Output, Self::Error> {
    let buf = self.0.end().map_err(CServiceDecoderError)?;
    let (addr_buf, port_buf) = buf.split_array::<16, 2>();
    Ok(CService {
      addr: *addr_buf,
      port: u16::from_be_bytes(*port_buf),
    })
  }

  #[inline]
  fn read_limit(&self) -> usize {
    self.0.read_limit()
  }
}

impl encoding::Decodable for CService {
  type Decoder = CServiceDecoder;
  fn decoder() -> Self::Decoder {
    CServiceDecoder::new()
  }
}

/// Purpose tag for an extended network info entry.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum NetInfoPurpose {
  /// Core P2P port.
  CoreP2p,
  /// Platform P2P port.
  PlatformP2p,
  /// Platform HTTPS port.
  PlatformHttps,
  /// Unrecognized purpose code.
  Unknown(u8),
}

impl NetInfoPurpose {
  /// Converts from a raw byte.
  pub const fn from_u8(val: u8) -> Self {
    match val {
      0 => Self::CoreP2p,
      1 => Self::PlatformP2p,
      2 => Self::PlatformHttps,
      other => Self::Unknown(other),
    }
  }

  /// Converts to a raw byte.
  pub const fn to_u8(self) -> u8 {
    match self {
      Self::CoreP2p => 0,
      Self::PlatformP2p => 1,
      Self::PlatformHttps => 2,
      Self::Unknown(v) => v,
    }
  }
}

impl fmt::Display for NetInfoPurpose {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    match self {
      Self::CoreP2p => write!(f, "core_p2p"),
      Self::PlatformP2p => write!(f, "platform_p2p"),
      Self::PlatformHttps => write!(f, "platform_https"),
      Self::Unknown(v) => write!(f, "unknown({v})"),
    }
  }
}

/// A single network info entry within a purpose group.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum NetInfoEntry {
  /// ADDRv1-style IP + port.
  Service(CService),
  /// Domain name + port.
  Domain {
    /// The domain name as raw bytes.
    name: Vec<u8>,
    /// Network port (big-endian on wire).
    port: u16,
  },
  /// Invalid / placeholder entry.
  Invalid,
}

/// Extended network info for v3+ ProRegTx / ProUpServTx.
///
/// Contains a versioned list of purpose-grouped network entries (core P2P,
/// platform P2P, platform HTTPS).
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct ExtendedNetInfo {
  /// Format version.
  pub version: u8,
  /// Purpose-grouped entries.
  pub entries: Vec<(NetInfoPurpose, Vec<NetInfoEntry>)>,
}

/// Maximum number of purpose groups.
const MAX_PURPOSES: usize = 8;
/// Maximum entries per purpose.
const MAX_ENTRIES: usize = 8;
/// Maximum domain name length.
const MAX_DOMAIN: usize = 256;

impl ExtendedNetInfo {
  /// Decodes from a raw byte slice.
  ///
  /// # Errors
  ///
  /// Returns `DecodeError` if the data is malformed.
  pub fn decode(data: &[u8]) -> Result<Self, crate::error::DecodeError> {
    use crate::wire;

    let sl = &mut &data[..];
    let version = wire::read_u8(sl)?;
    let purpose_count = wire::read_compact_size(sl, MAX_PURPOSES)?;

    let mut entries = Vec::with_capacity(purpose_count);
    for _ in 0..purpose_count {
      let purpose = NetInfoPurpose::from_u8(wire::read_u8(sl)?);
      let entry_count = wire::read_compact_size(sl, MAX_ENTRIES)?;
      let mut group = Vec::with_capacity(entry_count);

      for _ in 0..entry_count {
        let entry_type = wire::read_u8(sl)?;
        let entry = match entry_type {
          0x01 => NetInfoEntry::Service(CService {
            addr: wire::read_array(sl)?,
            port: wire::read_u16_be(sl)?,
          }),
          0x02 => {
            let name_len = wire::read_compact_size(sl, MAX_DOMAIN)?;
            let name = wire::read_bytes(sl, name_len)?.to_vec();
            let port = wire::read_u16_be(sl)?;
            NetInfoEntry::Domain { name, port }
          }
          _ => NetInfoEntry::Invalid,
        };
        group.push(entry);
      }

      entries.push((purpose, group));
    }

    Ok(Self { version, entries })
  }
}
