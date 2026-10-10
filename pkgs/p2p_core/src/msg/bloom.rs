//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! BIP37 bloom filter.

use crate::codec::impl_p2p;
use crate::prelude::*;

use dash_primitives::hash_impl;
use dash_types::codec::{self, BaseCodec, DecodeError, EncodeBuf};
use dash_types::type_id::{TypeId, Unencodable};
use dash_types::Checkable;

use core::fmt;

/// Largest filter bit array, in bytes.
const MAX_BLOOM_FILTER_SIZE: usize = 36_000;

/// Largest number of hash functions.
const MAX_HASH_FUNCS: u32 = 50;

/// BIP37 bloom filter.
#[derive(Clone, Debug, Default, Eq, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub struct BloomFilter {
  /// Filter bit array. Decoding rejects more than 36000 bytes.
  #[cfg_attr(feature = "serde", serde(with = "dash_types::serialize::hex"))]
  pub data: Vec<u8>,
  /// Number of hash functions.
  pub hash_funcs: u32,
  /// Seed added to every hash.
  pub tweak: u32,
  /// Update policy. The low two bits select it and the rest are reserved, so
  /// any byte decodes.
  pub flags: u8,
}

impl_p2p!(BloomFilter);

impl BaseCodec for BloomFilter {
  fn decode(data: &mut &[u8]) -> Result<Self, DecodeError> {
    Ok(Self {
      data: codec::read_bytes_limited(data, MAX_BLOOM_FILTER_SIZE)?.to_vec(),
      hash_funcs: u32::decode(data)?,
      tweak: u32::decode(data)?,
      flags: u8::decode(data)?,
    })
  }

  fn encode(&self, buf: &mut impl EncodeBuf) {
    self.data.encode(buf);
    self.hash_funcs.encode(buf);
    self.tweak.encode(buf);
    self.flags.encode(buf);
  }
}

/// Bloom filter size failure.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Unencodable)]
pub enum BloomFilterInvalid {
  /// The bit array exceeds 36000 bytes.
  DataTooLarge { len: usize },
  /// The filter uses more than 50 hash functions.
  TooManyHashFuncs { count: u32 },
}

impl fmt::Display for BloomFilterInvalid {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    match self {
      Self::DataTooLarge { len } => write!(f, "bloom filter data {len} bytes exceeds {MAX_BLOOM_FILTER_SIZE}"),
      Self::TooManyHashFuncs { count } => write!(f, "bloom filter hash funcs {count} exceeds {MAX_HASH_FUNCS}"),
    }
  }
}

impl Checkable for BloomFilter {
  type Error = BloomFilterInvalid;

  fn check(&self) -> Option<Self::Error> {
    if self.data.len() > MAX_BLOOM_FILTER_SIZE {
      return Some(BloomFilterInvalid::DataTooLarge { len: self.data.len() });
    }
    (self.hash_funcs > MAX_HASH_FUNCS).then_some(BloomFilterInvalid::TooManyHashFuncs { count: self.hash_funcs })
  }
}

hash_impl!(BloomFilter);

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "test code")]
mod tests {
  use super::{BloomFilter, BloomFilterInvalid, MAX_BLOOM_FILTER_SIZE};
  use crate::prelude::*;

  use bitcoin_consensus_encoding::{decode_from_slice, encode_to_vec};
  use dash_types::codec::{BaseCodec, DecodeError};
  use dash_types::Checkable;
  use rstest::rstest;

  fn filter(len: usize, hash_funcs: u32) -> BloomFilter {
    BloomFilter {
      data: vec![0xaa; len],
      hash_funcs,
      ..BloomFilter::default()
    }
  }

  #[rstest]
  #[case::at_limit(MAX_BLOOM_FILTER_SIZE, true)]
  #[case::past_limit(MAX_BLOOM_FILTER_SIZE + 1, false)]
  fn decodes_at_most_36000_data_bytes(#[case] len: usize, #[case] accepted: bool) {
    let raw = encode_to_vec(&filter(len, 0));
    let decoded = BloomFilter::decode(&mut raw.as_slice());
    if accepted {
      assert_eq!(decoded, Ok(filter(len, 0)));
    } else {
      assert_eq!(
        decoded,
        Err(DecodeError::CompactSizeExceedsLimit {
          limit: MAX_BLOOM_FILTER_SIZE,
          value: len as u64,
        })
      );
    }
  }

  #[rstest]
  #[case::empty(0, 0, None)]
  #[case::at_limits(MAX_BLOOM_FILTER_SIZE, 50, None)]
  #[case::data_past_limit(MAX_BLOOM_FILTER_SIZE + 1, 0, Some(BloomFilterInvalid::DataTooLarge { len: MAX_BLOOM_FILTER_SIZE + 1 }))]
  #[case::funcs_past_limit(0, 51, Some(BloomFilterInvalid::TooManyHashFuncs { count: 51 }))]
  #[case::funcs_max(0, u32::MAX, Some(BloomFilterInvalid::TooManyHashFuncs { count: u32::MAX }))]
  fn checks_the_size_constraints(
    #[case] len: usize,
    #[case] hash_funcs: u32,
    #[case] expected: Option<BloomFilterInvalid>,
  ) {
    assert_eq!(filter(len, hash_funcs).check(), expected);
  }

  #[rstest]
  fn default_is_the_ten_byte_empty_filter() {
    assert_eq!(encode_to_vec(&BloomFilter::default()), [0; 10]);
  }

  #[rstest]
  #[case::none(0)]
  #[case::p2pubkey_only(2)]
  #[case::reserved(0xff)]
  fn any_flags_byte_round_trips(#[case] flags: u8) {
    let filter = BloomFilter {
      data: vec![0xaa, 0xbb, 0xcc],
      hash_funcs: 9,
      tweak: 0x0003_e96e,
      flags,
    };
    let raw = [&[3, 0xaa, 0xbb, 0xcc, 9, 0, 0, 0, 0x6e, 0xe9, 0x03, 0][..], &[flags]].concat();
    assert_eq!(encode_to_vec(&filter), raw);
    assert_eq!(decode_from_slice::<BloomFilter>(&raw).unwrap(), filter);
  }
}
