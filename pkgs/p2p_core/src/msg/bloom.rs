//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! BIP37 bloom filter.

use crate::codec::codec_p2p;
use crate::prelude::*;

use dash_types::type_id::TypeId;

/// BIP37 bloom filter.
#[derive(Clone, Debug, Default, Eq, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub struct BloomFilter {
  /// Filter bit array.
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

codec_p2p!(BloomFilter {
  data,
  hash_funcs,
  tweak,
  flags
});

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "test code")]
mod tests {
  use super::BloomFilter;
  use crate::prelude::*;

  use bitcoin_consensus_encoding::{decode_from_slice, encode_to_vec};
  use rstest::rstest;

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
