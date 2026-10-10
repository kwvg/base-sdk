//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! AssetUnlock (type 9): Platform to L1.

use super::{payload_hash, QuorumHash};
use crate::codec::impl_payload;
use crate::hash_impl;
use crate::types::{BlsScheme, BlsSig};

use dash_num::Hash256;
use dash_types::codec::{BaseCodec, DecodeError, EncodeBuf};
use dash_types::type_id::{TypeId, Unencodable};
use dash_types::{Checkable, CompactSize};

use core::fmt;

/// AssetUnlock: Platform-to-L1 (type 9).
#[derive(Clone, Debug, Eq, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub struct AssetUnlock {
  /// Payload version.
  pub version: u8,
  /// Monotonic withdrawal sequence number.
  pub index: u64,
  /// Duffs deducted from withdrawal.
  pub fee: u32,
  /// Requested block height.
  pub requested_height: u32,
  /// Quorum hash.
  pub quorum_hash: QuorumHash,
  /// Quorum BLS authorization signature, always in the basic scheme.
  #[cfg_attr(feature = "serde", serde(deserialize_with = "crate::serialize::bls::sig_basic"))]
  pub quorum_sig: BlsSig,
}

impl_payload!(AssetUnlock);

impl BaseCodec for AssetUnlock {
  fn decode(data: &mut &[u8]) -> Result<Self, DecodeError> {
    Ok(Self {
      version: u8::decode(data)?,
      index: u64::decode(data)?,
      fee: u32::decode(data)?,
      requested_height: u32::decode(data)?,
      quorum_hash: QuorumHash::decode(data)?,
      // Asset unlocks arrive with v20, after the v19 switch to the basic
      // scheme.
      quorum_sig: BlsSig::decode(data, BlsScheme::Basic)?,
    })
  }

  fn encode(&self, buf: &mut impl EncodeBuf) {
    self.version.encode(buf);
    self.index.encode(buf);
    self.fee.encode(buf);
    self.requested_height.encode(buf);
    self.quorum_hash.encode(buf);
    self.quorum_sig.encode(buf);
  }
}

/// Most outputs an asset unlock transaction may carry.
pub const MAXIMUM_WITHDRAWALS: usize = 32;

/// Size of the trailing `requested_height`, `quorum_hash` and `quorum_sig`
/// fields, which Platform rewrites when it re-signs an expired withdrawal.
pub const ASSET_UNLOCK_QUORUM_INFO_SIZE: usize = 4 + 32 + 96;

/// Serialized size of an asset unlock payload.
pub const ASSET_UNLOCK_PAYLOAD_SIZE: usize = 1 + 8 + 4 + ASSET_UNLOCK_QUORUM_INFO_SIZE;

/// First payload version whose txid leaves out the quorum signing fields.
pub const ASSET_UNLOCK_STABLE_TXID_VERSION: u8 = 2;

/// Asset unlock validation failure.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Unencodable)]
pub enum AssetUnlockInvalid {
  /// `bad-assetunlocktx-version`
  BadVersion { version: u8 },
  /// `bad-txns-assetunlock-fee-outofrange`
  FeeOutOfRange { fee: u32 },
  /// `bad-assetunlocktx-payload`
  BadPayload,
  /// `bad-assetunlocktx-have-input`
  HaveInput,
  /// `bad-assetunlocktx-too-many-outs`
  TooManyOutputs { count: usize },
}

impl core::fmt::Display for AssetUnlockInvalid {
  fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
    match self {
      Self::BadVersion { version } => write!(f, "bad-assetunlocktx-version: {version}"),
      Self::FeeOutOfRange { fee } => write!(f, "bad-txns-assetunlock-fee-outofrange: {fee}"),
      Self::BadPayload => write!(f, "bad-assetunlocktx-payload"),
      Self::HaveInput => write!(f, "bad-assetunlocktx-have-input"),
      Self::TooManyOutputs { count } => write!(f, "bad-assetunlocktx-too-many-outs: {count}"),
    }
  }
}

impl Checkable for AssetUnlock {
  type Error = AssetUnlockInvalid;

  fn check(&self) -> Option<Self::Error> {
    if self.version == 0 || self.version > 2 {
      return Some(AssetUnlockInvalid::BadVersion { version: self.version });
    }

    // A non-canonical signature counts as a payload decode failure.
    if !self.quorum_sig.is_canonical() {
      return Some(AssetUnlockInvalid::BadPayload);
    }

    if self.fee == 0 {
      return Some(AssetUnlockInvalid::FeeOutOfRange { fee: self.fee });
    }

    None
  }
}

hash_impl!(AssetUnlock);

/// Prefix of the asset unlock signing request id.
const REQUEST_ID_PREFIX: [u8; 6] = *b"plwdtx";

impl AssetUnlock {
  /// Quorum signing request id, shared by every instance and payload version
  /// of one withdrawal.
  pub fn request_id(&self) -> Hash256 {
    payload_hash(|buf| {
      CompactSize::from(REQUEST_ID_PREFIX.len()).encode(buf);
      REQUEST_ID_PREFIX.encode(buf);
      self.index.encode(buf);
    })
  }
}

impl fmt::Display for AssetUnlock {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "AssetUnlock {{ v{}, index: {} }}", self.version, self.index,)
  }
}

#[cfg(all(test, feature = "serde"))]
#[expect(clippy::unwrap_used, reason = "test code")]
mod tests {
  use super::*;
  use crate::prelude::*;

  use dash_dev::{assert_serde_rt, check_sptx, Corpus};
  use dash_types::Numeric;
  use hex_conservative::hex;
  use rstest::rstest;

  #[rstest]
  fn corpus_assetunlock() {
    let corpus = Corpus::open(env!("CARGO_MANIFEST_DIR"), "assetunlock");
    let items = corpus.entries::<AssetUnlock>("assetunlock", check_sptx);
    assert_serde_rt("assetunlock", &items);
  }

  #[rstest]
  fn signature_is_basic() {
    let corpus = Corpus::open(env!("CARGO_MANIFEST_DIR"), "assetunlock");
    for (label, item) in corpus.entries::<AssetUnlock>("assetunlock", |_, _, _| {}) {
      assert_eq!(item.quorum_sig.scheme(), BlsScheme::Basic, "{label}");
    }
  }
  #[rstest]
  #[case::v0(0, Some(AssetUnlockInvalid::BadVersion { version: 0 }))]
  #[case::v1(1, None)]
  #[case::v2(2, None)]
  #[case::v3(3, Some(AssetUnlockInvalid::BadVersion { version: 3 }))]
  fn payload_versions_1_and_2_are_known(#[case] version: u8, #[case] expected: Option<AssetUnlockInvalid>) {
    let corpus = Corpus::open(env!("CARGO_MANIFEST_DIR"), "assetunlock");
    let mut item = corpus
      .entries::<AssetUnlock>("assetunlock", |_, _, _| {})
      .into_values()
      .next()
      .unwrap();
    item.version = version;
    assert_eq!(item.check(), expected);
  }

  #[rstest]
  fn request_id_hashes_the_prefix_and_the_index() {
    // Python hashlib gives the expected id over `06 "plwdtx"` and the index
    // 10464 as a little-endian `u64`.
    let expected = Hash256::from_lendian(hex!("2551d75f2d9f876334291340dddd62a73c12964b38caa014c5d5e94c955a7202"));
    let corpus = Corpus::open(env!("CARGO_MANIFEST_DIR"), "assetunlock");
    let items = corpus.entries::<AssetUnlock>("assetunlock", |_, _, _| {});
    let mut item = items["65fc488b35abd172726238a16cc71ef11eecb034ce05991e9a3e5ba4fd85094f"].clone();
    assert_eq!(item.request_id(), expected);

    item.version = 2;
    item.requested_height += 1;
    item.quorum_hash = QuorumHash::from_lendian([0x11; 32]);
    assert_eq!(item.request_id(), expected);
    item.index += 1;
    assert_ne!(item.request_id(), expected);
  }

  #[rstest]
  fn non_canonical_signature_is_a_bad_payload() {
    let corpus = Corpus::open(env!("CARGO_MANIFEST_DIR"), "assetunlock");
    let mut item = corpus
      .entries::<AssetUnlock>("assetunlock", |_, _, _| {})
      .into_values()
      .next()
      .unwrap();
    assert_eq!(item.check(), None);
    item.quorum_sig = item.quorum_sig.corrupted();
    assert_eq!(item.check(), Some(AssetUnlockInvalid::BadPayload));
    assert_eq!(AssetUnlockInvalid::BadPayload.to_string(), "bad-assetunlocktx-payload");
  }
}
