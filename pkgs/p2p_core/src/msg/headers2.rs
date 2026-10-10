//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Compressed header messages.

use crate::codec::{codec_p2p, impl_p2p};
use crate::error::{check_count, TooManyEntries};
use crate::macros::VersionedPayload;
use crate::msg::headers::{check_chain, NonContinuousHeaders, MAX_LOCATOR_SZ};
use crate::prelude::*;
use crate::version::ProtocolVersion;
use crate::P2pDecodeError;

use dash_primitives::{hash_impl, BlockHash, BlockHeader, MerkleRoot};
use dash_types::codec::{BaseCodec, DecodeError, EncodeBuf};
use dash_types::type_id::{TypeId, Unencodable};
use dash_types::{Checkable, CompactSize, Hashable};

/// Maximum headers per message below protocol 70235.
const MAX_HEADERS: usize = 2_000;

/// Maximum headers per message from protocol 70235.
const MAX_HEADERS_COMPRESSED: usize = 8_000;

/// Maximum entries in the MRU version cache.
const MAX_VERSION_CACHE: usize = 7;

// Bits 0-2: version offset (0 = full version present, 1-7 = MRU cache index).
const VERSION_OFFSET_MASK: u8 = 0b0000_0111;

// Bit 3: prev_blockhash present.
const FLAG_PREV_HASH: u8 = 0b0000_1000;

// Bit 4: timestamp mode (0 = i16 delta, 1 = full u32).
const FLAG_TIMESTAMP_FULL: u8 = 0b0001_0000;

// Bit 5: nbits present.
const FLAG_NBITS: u8 = 0b0010_0000;

/// Stateful compressor/decompressor for a stream of block headers.
#[derive(Clone, Debug, Eq, Hash, PartialEq, Unencodable)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct CompressionState {
  /// Most recently used versions, newest first. More than seven entries
  /// would overflow the 3-bit version offset.
  #[cfg_attr(feature = "serde", serde(deserialize_with = "deserialize_version_cache"))]
  version_cache: Vec<i32>,
  /// Previous fully-resolved header.
  prev_header: Option<BlockHeader>,
  /// Cached block hash of `prev_header`.
  #[cfg_attr(feature = "serde", serde(skip))]
  prev_block_hash: Option<BlockHash>,
}

impl CompressionState {
  /// Creates fresh state with an empty cache and no previous header.
  pub fn new() -> Self {
    Self {
      version_cache: Vec::with_capacity(MAX_VERSION_CACHE),
      prev_header: None,
      prev_block_hash: None,
    }
  }

  /// Returns the most recently used versions, newest first.
  pub fn version_cache(&self) -> &[i32] {
    &self.version_cache
  }

  /// Returns the previous fully-resolved header.
  pub fn prev_header(&self) -> Option<&BlockHeader> {
    self.prev_header.as_ref()
  }

  /// Moves the version at `position` to the front of the cache.
  fn mark_version_mru(&mut self, position: usize) {
    let v = self.version_cache.remove(position);
    self.version_cache.insert(0, v);
  }

  /// Inserts `version` at the front, evicting the oldest if full.
  fn save_version_mru(&mut self, version: i32) {
    if self.version_cache.len() >= MAX_VERSION_CACHE {
      self.version_cache.pop();
    }
    self.version_cache.insert(0, version);
  }

  /// Finds the cache position (0-based) for a version, if cached.
  fn find_version(&self, version: i32) -> Option<usize> {
    self.version_cache.iter().position(|&v| v == version)
  }

  /// Returns cached hash, recomputing from `prev_header` if the cache is cold.
  fn prev_hash(&mut self) -> Option<BlockHash> {
    if self.prev_block_hash.is_none() {
      self.prev_block_hash = self.prev_header.as_ref().map(|h| h.hash());
    }
    self.prev_block_hash
  }

  /// Decodes one compressed header, advancing the slice and state.
  pub(crate) fn decode_header(&mut self, sl: &mut &[u8]) -> Result<BlockHeader, DecodeError> {
    let flags = u8::decode(sl)?;
    let version_offset = flags & VERSION_OFFSET_MASK;

    let version = if version_offset == 0 {
      let v = i32::decode(sl)?;
      self.save_version_mru(v);
      v
    } else {
      let pos = (version_offset - 1) as usize;
      if pos >= self.version_cache.len() {
        return Err(DecodeError::InvalidValue {
          expected: (0..self.version_cache.len() as u64).collect(),
          actual: pos as u64,
        });
      }
      let v = self.version_cache[pos];
      self.mark_version_mru(pos);
      v
    };

    let prev_hash = if flags & FLAG_PREV_HASH != 0 {
      BlockHash::decode(sl)?
    } else {
      self.prev_hash().ok_or_else(|| no_predecessor(FLAG_PREV_HASH))?
    };

    let merkle_root = MerkleRoot::decode(sl)?;

    let time = if flags & FLAG_TIMESTAMP_FULL != 0 {
      u32::decode(sl)?
    } else {
      let delta = i16::decode(sl)?;
      let prev = self
        .prev_header
        .as_ref()
        .ok_or_else(|| no_predecessor(FLAG_TIMESTAMP_FULL))?;
      (prev.time as i64 + delta as i64) as u32
    };

    let bits = if flags & FLAG_NBITS != 0 {
      u32::decode(sl)?
    } else {
      self
        .prev_header
        .as_ref()
        .ok_or_else(|| no_predecessor(FLAG_NBITS))?
        .bits
    };

    let nonce = u32::decode(sl)?;

    let header = BlockHeader {
      version,
      prev_hash,
      merkle_root,
      time,
      bits,
      nonce,
    };
    self.prev_block_hash = Some(header.hash());
    self.prev_header = Some(header);
    Ok(header)
  }

  /// Encodes one header in compressed form, advancing the state.
  pub(crate) fn encode_header(&mut self, header: &BlockHeader, buf: &mut impl EncodeBuf) {
    let mut flags: u8 = 0;

    let version_offset = match self.find_version(header.version) {
      Some(pos) => (pos + 1) as u8,
      None => 0,
    };
    flags |= version_offset & VERSION_OFFSET_MASK;

    let need_prev_hash = match self.prev_hash() {
      Some(hash) => header.prev_hash != hash,
      None => true,
    };
    if need_prev_hash {
      flags |= FLAG_PREV_HASH;
    }

    // The offset is taken modulo 2^32, so a header older than its predecessor
    // is sent in full while a forward wrap past `u32::MAX` is compressed.
    let time_delta = self
      .prev_header
      .as_ref()
      .map(|prev| header.time.wrapping_sub(prev.time))
      .filter(|d| *d <= i16::MAX as u32)
      .map(|d| d as i16);
    if time_delta.is_none() {
      flags |= FLAG_TIMESTAMP_FULL;
    }

    let need_nbits = match &self.prev_header {
      Some(prev) => header.bits != prev.bits,
      None => true,
    };
    if need_nbits {
      flags |= FLAG_NBITS;
    }

    buf.push(flags);

    if version_offset == 0 {
      header.version.encode(buf);
      self.save_version_mru(header.version);
    } else {
      let pos = (version_offset - 1) as usize;
      self.mark_version_mru(pos);
    }

    if need_prev_hash {
      header.prev_hash.encode(buf);
    }

    header.merkle_root.encode(buf);

    match time_delta {
      Some(d) => d.encode(buf),
      None => header.time.encode(buf),
    }

    if need_nbits {
      header.bits.encode(buf);
    }

    header.nonce.encode(buf);
    self.prev_block_hash = Some(header.hash());
    self.prev_header = Some(*header);
  }
}

/// Error for a first header that omits the field behind `flag`.
fn no_predecessor(flag: u8) -> DecodeError {
  DecodeError::InvalidValue {
    expected: vec![u64::from(flag)],
    actual: 0,
  }
}

/// Rejects a cache longer than the 3-bit version offset can index.
#[cfg(feature = "serde")]
fn deserialize_version_cache<'de, D: ::serde::Deserializer<'de>>(deserializer: D) -> Result<Vec<i32>, D::Error> {
  let cache = <Vec<i32> as ::serde::Deserialize>::deserialize(deserializer)?;
  if cache.len() > MAX_VERSION_CACHE {
    return Err(::serde::de::Error::invalid_length(cache.len(), &"at most 7 versions"));
  }
  Ok(cache)
}

impl Default for CompressionState {
  fn default() -> Self {
    Self::new()
  }
}

/// Requests compressed block headers starting from a locator.
#[derive(Clone, Debug, Eq, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct GetHeaders2 {
  /// Protocol version.
  pub version: ProtocolVersion,
  /// Block locator hashes (newest first).
  pub locator_hashes: Vec<BlockHash>,
  /// Stop hash (zero to get as many as possible).
  pub hash_stop: BlockHash,
}

codec_p2p!(GetHeaders2 {
  version,
  locator_hashes,
  hash_stop
});

impl Checkable for GetHeaders2 {
  type Error = TooManyEntries;

  fn check(&self) -> Option<Self::Error> {
    check_count(self.locator_hashes.len(), MAX_LOCATOR_SZ)
  }
}

/// Response carrying delta-compressed block headers.
#[derive(Clone, Debug, Eq, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct Headers2 {
  /// Fully resolved block headers. A peer below protocol 70235 rejects more
  /// than 2000 headers, and a peer at 70235 or above more than 8000.
  pub headers: Vec<BlockHeader>,
}

impl_p2p!(Headers2);

/// Decodes a message as sent at [`ProtocolVersion::CURRENT`].
impl BaseCodec for Headers2 {
  fn decode(data: &mut &[u8]) -> Result<Self, DecodeError> {
    Self::decode_headers(data, Self::max_headers(ProtocolVersion::CURRENT))
  }

  fn encode(&self, buf: &mut impl EncodeBuf) {
    CompactSize::from(self.headers.len()).encode(buf);
    let mut state = CompressionState::new();
    for h in &self.headers {
      state.encode_header(h, buf);
    }
  }
}

impl Checkable for Headers2 {
  type Error = NonContinuousHeaders;

  fn check(&self) -> Option<Self::Error> {
    check_chain(&self.headers)
  }
}

hash_impl!(Headers2);

impl Headers2 {
  /// Largest number of headers in a message at `version`.
  fn max_headers(version: ProtocolVersion) -> usize {
    if version >= ProtocolVersion::INCREASE_MAX_HEADERS2 {
      MAX_HEADERS_COMPRESSED
    } else {
      MAX_HEADERS
    }
  }

  /// Decodes a message of at most `limit` headers.
  fn decode_headers(data: &mut &[u8], limit: usize) -> Result<Self, DecodeError> {
    let count = CompactSize::decode(data)?.into_len(limit)?;
    let mut state = CompressionState::new();
    let mut headers = Vec::with_capacity(count);
    for _ in 0..count {
      headers.push(state.decode_header(data)?);
    }
    Ok(Self { headers })
  }
}

impl VersionedPayload for Headers2 {
  fn decode_versioned(payload: &[u8], version: ProtocolVersion) -> Result<Self, P2pDecodeError> {
    let mut data = payload;
    let msg = Self::decode_headers(&mut data, Self::max_headers(version))?;
    if !data.is_empty() {
      return Err(DecodeError::TrailingBytes { remaining: data.len() }.into());
    }
    Ok(msg)
  }

  fn encode_versioned(&self, buf: &mut Vec<u8>, _version: ProtocolVersion) {
    self.encode(buf);
  }
}

#[cfg(all(test, feature = "serde"))]
mod tests {
  use super::*;

  use dash_dev::{assert_serde_rt, check_wire, Corpus};
  use rstest::rstest;

  #[rstest]
  #[case::empty(0, None)]
  #[case::at_limit(MAX_LOCATOR_SZ, None)]
  #[case::past_limit(MAX_LOCATOR_SZ + 1, Some(TooManyEntries { count: MAX_LOCATOR_SZ + 1, limit: MAX_LOCATOR_SZ }))]
  fn locators_carry_at_most_101_hashes(#[case] count: usize, #[case] expected: Option<TooManyEntries>) {
    let msg = GetHeaders2 {
      version: ProtocolVersion::CURRENT,
      locator_hashes: vec![BlockHash::default(); count],
      hash_stop: BlockHash::default(),
    };
    assert_eq!(msg.check(), expected);
  }

  #[rstest]
  fn corpus_getheaders2() {
    let corpus = Corpus::open(env!("CARGO_MANIFEST_DIR"), "headers2");
    let items = corpus.entries::<GetHeaders2>("getheaders2", check_wire);
    assert_serde_rt("getheaders2", &items);
  }

  fn header_at(prev_hash: BlockHash, time: u32) -> BlockHeader {
    BlockHeader {
      version: 0x2000_0000,
      prev_hash,
      merkle_root: MerkleRoot::default(),
      time,
      bits: 0x1e0f_fff0,
      nonce: 0,
    }
  }

  #[rstest]
  #[case::zero(1_000, 1_000, true)]
  #[case::max_offset(1_000, 33_767, true)]
  #[case::past_max_offset(1_000, 33_768, false)]
  #[case::negative(1_000, 999, false)]
  #[case::forward_wrap(u32::MAX - 10, 5, true)]
  fn compresses_time_offsets_modulo_2_32(#[case] prev_time: u32, #[case] time: u32, #[case] compressed: bool) {
    let first = header_at(BlockHash::default(), prev_time);
    let second = header_at(first.hash(), time);
    let mut state = CompressionState::new();
    state.encode_header(&first, &mut Vec::new());
    let mut buf = Vec::new();
    state.encode_header(&second, &mut buf);
    assert_eq!(buf[0] & FLAG_TIMESTAMP_FULL == 0, compressed);

    let msg = Headers2 {
      headers: vec![first, second],
    };
    let mut wire = Vec::new();
    msg.encode(&mut wire);
    assert_eq!(Headers2::decode(&mut wire.as_slice()), Ok(msg));
  }

  #[rstest]
  #[case::version(1, FLAG_PREV_HASH | FLAG_TIMESTAMP_FULL | FLAG_NBITS)]
  #[case::prev_hash(0, FLAG_TIMESTAMP_FULL | FLAG_NBITS)]
  #[case::time(0, FLAG_PREV_HASH | FLAG_NBITS)]
  #[case::bits(0, FLAG_PREV_HASH | FLAG_TIMESTAMP_FULL)]
  fn rejects_a_first_header_delta_coded(#[case] version_offset: u8, #[case] full: u8) {
    let first = header_at(BlockHash::default(), 1_000);
    let mut wire = vec![1, version_offset | full];
    if version_offset == 0 {
      first.version.encode(&mut wire);
    }
    if full & FLAG_PREV_HASH != 0 {
      first.prev_hash.encode(&mut wire);
    }
    first.merkle_root.encode(&mut wire);
    if full & FLAG_TIMESTAMP_FULL != 0 {
      first.time.encode(&mut wire);
    } else {
      0i16.encode(&mut wire);
    }
    if full & FLAG_NBITS != 0 {
      first.bits.encode(&mut wire);
    }
    first.nonce.encode(&mut wire);
    assert!(matches!(
      Headers2::decode(&mut wire.as_slice()),
      Err(DecodeError::InvalidValue { .. })
    ));
  }

  #[rstest]
  fn caps_the_version_cache() {
    let mut state = CompressionState::new();
    let mut prev_hash = BlockHash::default();
    for version in 1..=9 {
      let header = BlockHeader {
        version,
        ..header_at(prev_hash, 1_000)
      };
      state.encode_header(&header, &mut Vec::new());
      prev_hash = header.hash();
    }
    assert_eq!(state.version_cache(), [9, 8, 7, 6, 5, 4, 3]);
  }

  #[rstest]
  #[case::full(7, true)]
  #[case::overfull(8, false)]
  fn deserializes_at_most_seven_versions(#[case] len: usize, #[case] accepted: bool) {
    use ::serde::de::value::{Error, SeqDeserializer};

    let versions = SeqDeserializer::<_, Error>::new(core::iter::repeat_n(1i32, len));
    assert_eq!(deserialize_version_cache(versions).is_ok(), accepted);
  }

  #[rstest]
  fn tracks_the_prev_header_and_its_hash() {
    let first = header_at(BlockHash::default(), 1_000);
    let mut state = CompressionState::new();
    state.encode_header(&first, &mut Vec::new());
    assert_eq!(state.prev_header(), Some(&first));

    let mut buf = Vec::new();
    state.encode_header(&header_at(first.hash(), 1_001), &mut buf);
    assert_eq!(buf[0] & FLAG_PREV_HASH, 0);
  }

  #[rstest]
  fn rejects_a_broken_link() {
    let first = header_at(BlockHash::default(), 1_000);
    let chained = Headers2 {
      headers: vec![first, header_at(first.hash(), 1_001)],
    };
    assert_eq!(chained.check(), None);
    let broken = Headers2 {
      headers: vec![first, header_at(BlockHash::default(), 1_001)],
    };
    assert_eq!(broken.check(), Some(NonContinuousHeaders { index: 1 }));
  }

  /// A count within the cap reads past the prefix and fails on the missing
  /// headers, so only a count past the cap reports the limit.
  fn cap_error(limit: usize, count: usize) -> DecodeError {
    if count > limit {
      DecodeError::CompactSizeExceedsLimit {
        limit,
        value: count as u64,
      }
    } else {
      DecodeError::Eof {
        needed: 1,
        remaining: 0,
      }
    }
  }

  #[rstest]
  #[case::below_switch_at_limit(ProtocolVersion(70234), MAX_HEADERS, MAX_HEADERS)]
  #[case::below_switch_past_limit(ProtocolVersion(70234), MAX_HEADERS, MAX_HEADERS + 1)]
  #[case::at_switch(ProtocolVersion::INCREASE_MAX_HEADERS2, MAX_HEADERS_COMPRESSED, MAX_HEADERS + 1)]
  #[case::at_limit(
    ProtocolVersion::INCREASE_MAX_HEADERS2,
    MAX_HEADERS_COMPRESSED,
    MAX_HEADERS_COMPRESSED
  )]
  #[case::past_limit(ProtocolVersion::INCREASE_MAX_HEADERS2, MAX_HEADERS_COMPRESSED, MAX_HEADERS_COMPRESSED + 1)]
  fn headers2_cap_follows_the_peer_version(
    #[case] version: ProtocolVersion,
    #[case] limit: usize,
    #[case] count: usize,
  ) {
    let mut payload = Vec::new();
    CompactSize::from(count).encode(&mut payload);
    assert_eq!(
      <Headers2 as VersionedPayload>::decode_versioned(&payload, version),
      Err(P2pDecodeError::from(cap_error(limit, count)))
    );
  }

  #[rstest]
  #[case::at_limit(MAX_HEADERS_COMPRESSED)]
  #[case::past_limit(MAX_HEADERS_COMPRESSED + 1)]
  fn headers2_decodes_at_the_current_version(#[case] count: usize) {
    let mut payload = Vec::new();
    CompactSize::from(count).encode(&mut payload);
    assert_eq!(
      Headers2::decode(&mut payload.as_slice()),
      Err(cap_error(MAX_HEADERS_COMPRESSED, count))
    );
  }

  #[rstest]
  fn headers2_round_trips_at_the_peer_version() {
    let first = header_at(BlockHash::default(), 1_000);
    let msg = Headers2 {
      headers: vec![first, header_at(first.hash(), 1_001)],
    };
    let mut payload = Vec::new();
    msg.encode_versioned(&mut payload, ProtocolVersion::CURRENT);
    assert_eq!(
      <Headers2 as VersionedPayload>::decode_versioned(&payload, ProtocolVersion::CURRENT),
      Ok(msg)
    );
    payload.push(0);
    assert!(matches!(
      <Headers2 as VersionedPayload>::decode_versioned(&payload, ProtocolVersion::CURRENT),
      Err(P2pDecodeError::Consensus(_))
    ));
  }

  #[rstest]
  fn corpus_headers2() {
    let corpus = Corpus::open(env!("CARGO_MANIFEST_DIR"), "headers2");
    let items = corpus.entries::<Headers2>("headers2", check_wire);
    assert_serde_rt("headers2", &items);
  }
}
