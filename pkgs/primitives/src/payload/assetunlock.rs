//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! AssetUnlock (type 9): Platform to L1.

use super::QuorumHash;
use crate::codec::codec_payload;

use dash_pkc::bls::{BlsScIetf, BlsSigBytes};
use dash_types::codec::Checkable;
use dash_types::{TypeId, Unencodable};

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
  /// Quorum BLS authorization signature.
  pub quorum_sig: BlsSigBytes<BlsScIetf>,
}

codec_payload!(AssetUnlock {
  version,
  index,
  fee,
  requested_height,
  quorum_hash,
  quorum_sig,
});

/// Asset unlock validation failure.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Unencodable)]
pub enum AssetUnlockInvalid {
  /// `bad-assetunlocktx-version`
  BadVersion { version: u8 },
  /// `bad-txns-assetunlock-fee-outofrange`
  FeeOutOfRange { fee: u32 },
}

impl core::fmt::Display for AssetUnlockInvalid {
  fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
    match self {
      Self::BadVersion { version } => write!(f, "bad-assetunlocktx-version: {version}"),
      Self::FeeOutOfRange { fee } => write!(f, "bad-txns-assetunlock-fee-outofrange: {fee}"),
    }
  }
}

impl Checkable for AssetUnlock {
  type Error = AssetUnlockInvalid;

  fn check(&self) -> Option<Self::Error> {
    if self.version == 0 || self.version > 1 {
      return Some(AssetUnlockInvalid::BadVersion { version: self.version });
    }

    if self.fee == 0 {
      return Some(AssetUnlockInvalid::FeeOutOfRange { fee: self.fee });
    }

    None
  }
}

impl fmt::Display for AssetUnlock {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "AssetUnlock {{ v{}, index: {} }}", self.version, self.index,)
  }
}

#[cfg(all(test, feature = "serde"))]
mod tests {
  use super::*;

  use dash_dev::{assert_serde_rt, check_sptx, load_corpus_file, read_corpus};
  use rstest::rstest;

  #[rstest]
  fn corpus_assetunlock() {
    let text = load_corpus_file(env!("CARGO_MANIFEST_DIR"), "assetunlock");
    let items = read_corpus::<AssetUnlock>(&text, "assetunlock", check_sptx);
    assert_serde_rt("assetunlock", &items);
  }
}
