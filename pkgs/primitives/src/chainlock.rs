//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! ChainLock signatures.

use crate::block::BlockHash;
use crate::codec_type;
use crate::payload::payload_hash;

use dash_num::Hash256;
use dash_pkc::bls::{BlsScIetf, BlsSigBytes};
use dash_types::codec::BaseCodec;
use dash_types::type_id::TypeId;
use dash_types::CompactSize;

use core::fmt;

/// Prefix of the ChainLock signing request id.
const REQUEST_ID_PREFIX: [u8; 5] = *b"clsig";

/// Quorum signature that locks a block at its height.
///
/// A ChainLock carries no version, so the signature is held as basic. Every
/// network buried v19, which switched quorums to the basic scheme, so only a
/// regtest chain with a deferred v19 height relays legacy ChainLocks.
#[derive(Clone, Debug, Eq, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub struct ChainLockSig {
  /// Height of the locked block, -1 in a null ChainLock.
  pub height: i32,
  /// Hash of the locked block.
  pub block_hash: BlockHash,
  /// Recovered quorum signature over the block hash.
  pub sig: BlsSigBytes<BlsScIetf>,
}

codec_type!(ChainLockSig {
  height,
  block_hash,
  sig
});

impl ChainLockSig {
  /// Tells whether the ChainLock locks no block.
  pub fn is_null(&self) -> bool {
    self.height == -1 && self.block_hash.is_null()
  }

  /// Quorum signing request id, which depends on the height alone.
  pub fn request_id(&self) -> Hash256 {
    payload_hash(|buf| {
      CompactSize::from(REQUEST_ID_PREFIX.len()).encode(buf);
      REQUEST_ID_PREFIX.encode(buf);
      self.height.encode(buf);
    })
  }
}

impl fmt::Display for ChainLockSig {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(
      f,
      "ChainLockSig {{ height: {}, block: {} }}",
      self.height, self.block_hash
    )
  }
}

#[cfg(test)]
mod tests {
  use super::ChainLockSig;
  use crate::block::BlockHash;
  use crate::prelude::*;

  use dash_num::Hash256;
  use dash_pkc::bls::BlsSigBytes;
  use dash_types::codec::BaseCodec;
  use dash_types::Numeric;
  use hex_conservative::hex;
  use rstest::rstest;

  fn clsig(height: i32, hash_byte: u8) -> ChainLockSig {
    ChainLockSig {
      height,
      block_hash: BlockHash::from_lendian([hash_byte; 32]),
      sig: BlsSigBytes::from_bytes([0xab; 96]),
    }
  }

  #[rstest]
  fn wire_is_height_hash_and_signature() {
    let item = clsig(0x0102_0304, 0x11);
    let mut wire = Vec::new();
    item.encode(&mut wire);
    let mut expected = vec![0x04, 0x03, 0x02, 0x01];
    expected.extend([0x11; 32]);
    expected.extend([0xab; 96]);
    assert_eq!(wire, expected);
    assert_eq!(ChainLockSig::decode(&mut wire.as_slice()), Ok(item));
  }

  #[rstest]
  #[case::mainnet_height(
    2_459_168,
    hex!("19a843f3117acc822d1fb7e98cf222683522098791021d3e28f98de38c1be411")
  )]
  #[case::null_height(-1, hex!("fec432f91d8a81162dfb2a9d4e2c44bef6814c7d626388aa3ea0d1f5d1ccd014"))]
  fn request_id_hashes_the_prefix_and_the_height(#[case] height: i32, #[case] expected: [u8; 32]) {
    // Python hashlib gives the expected id over `05 "clsig"` and the height
    // as a little-endian `i32`.
    let expected = Hash256::from_lendian(expected);
    assert_eq!(clsig(height, 0x11).request_id(), expected);
    assert_eq!(clsig(height, 0x22).request_id(), expected);
    assert_ne!(clsig(height.wrapping_add(1), 0x11).request_id(), expected);
  }

  #[rstest]
  #[case::null(-1, 0x00, true)]
  #[case::null_height_only(-1, 0x11, false)]
  #[case::null_hash_only(100, 0x00, false)]
  #[case::locked(100, 0x11, false)]
  fn null_chainlock_has_height_minus_1_and_a_null_hash(#[case] height: i32, #[case] hash_byte: u8, #[case] null: bool) {
    assert_eq!(clsig(height, hash_byte).is_null(), null);
  }

  #[cfg(feature = "serde")]
  #[rstest]
  fn serde_round_trips() {
    let item = clsig(100, 0x11);
    assert_eq!(dash_dev::from_json::<ChainLockSig>(&dash_dev::to_json(&item)), item);
  }
}
