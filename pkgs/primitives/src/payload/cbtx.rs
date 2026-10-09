//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! CoinbaseCommitment coinbase commitment payload (type 5).

use crate::codec::impl_payload;
use crate::types::{BlsScheme, BlsSig};
use crate::{hash_impl, MerkleRoot};

use bitcoin_units::BlockHeight;
use dash_types::codec::{BaseCodec, DecodeError, EncodeBuf};
use dash_types::type_id::{TypeId, Unencodable};
use dash_types::{Checkable, CompactSize};

use core::fmt;

/// CoinbaseCommitment -- coinbase commitment payload.
///
/// - v1: base fields (version, height, merkle_root_mn_list)
/// - v2: adds merkle_root_quorums
/// - v3: adds ChainLock proof and credit pool balance
#[derive(Clone, Debug, Eq, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub struct CoinbaseCommitment {
  /// Payload version (1, 2, or 3).
  pub version: u16,
  /// Block height.
  pub height: BlockHeight,
  /// Merkle root of the masternode list.
  pub merkle_root_mn_list: MerkleRoot,
  /// Merkle root of quorum commitments (v2+).
  pub merkle_root_quorums: Option<MerkleRoot>,
  /// Best ChainLock height difference (v3+), at most [`MAX_SIZE`] on the wire.
  ///
  /// [`MAX_SIZE`]: dash_types::MAX_SIZE
  pub best_cl_height_diff: Option<u32>,
  /// Best ChainLock BLS signature (v3+), always in the basic scheme.
  #[cfg_attr(
    feature = "serde",
    serde(default, deserialize_with = "crate::serialize::bls::sig_basic_opt")
  )]
  pub best_cl_signature: Option<BlsSig>,
  /// Credit pool balance in duffs (v3+).
  pub credit_pool_balance: Option<i64>,
}

impl_payload!(CoinbaseCommitment);

impl BaseCodec for CoinbaseCommitment {
  fn decode(data: &mut &[u8]) -> Result<Self, DecodeError> {
    let version = u16::decode(data)?;
    let height = BlockHeight::from_u32(u32::decode(data)?);
    let merkle_root_mn_list = MerkleRoot::decode(data)?;
    let merkle_root_quorums = if version >= 2 {
      Some(MerkleRoot::decode(data)?)
    } else {
      None
    };
    let (best_cl_height_diff, best_cl_signature, credit_pool_balance) = if version >= 3 {
      (
        Some(CompactSize::decode_checked_as::<u32>(data)?),
        // The signature first appears in CbTx v3, after the v19 switch to
        // the basic scheme.
        Some(BlsSig::decode(data, BlsScheme::Basic)?),
        Some(i64::decode(data)?),
      )
    } else {
      (None, None, None)
    };

    Ok(Self {
      version,
      height,
      merkle_root_mn_list,
      merkle_root_quorums,
      best_cl_height_diff,
      best_cl_signature,
      credit_pool_balance,
    })
  }

  fn encode(&self, buf: &mut impl EncodeBuf) {
    self.version.encode(buf);
    self.height.to_u32().encode(buf);
    self.merkle_root_mn_list.encode(buf);
    if let Some(root) = self.merkle_root_quorums {
      root.encode(buf);
    }
    if let (Some(diff), Some(sig), Some(bal)) = (
      self.best_cl_height_diff,
      self.best_cl_signature,
      self.credit_pool_balance,
    ) {
      CompactSize::from(u64::from(diff)).encode(buf);
      sig.encode(buf);
      bal.encode(buf);
    }
  }
}

/// Coinbase commitment validation failure.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Unencodable)]
pub enum CbTxInvalid {
  /// `bad-cbtx-version`
  BadVersion { version: u16 },
  /// `bad-cbtx-missing-field`
  MissingField,
  /// `bad-cbtx-unexpected-field`
  UnexpectedField,
  /// `bad-cbtx-payload`
  BadPayload,
}

impl core::fmt::Display for CbTxInvalid {
  fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
    match self {
      Self::BadVersion { version } => write!(f, "bad-cbtx-version: {version}"),
      Self::MissingField => write!(f, "bad-cbtx-missing-field"),
      Self::UnexpectedField => write!(f, "bad-cbtx-unexpected-field"),
      Self::BadPayload => write!(f, "bad-cbtx-payload"),
    }
  }
}

impl Checkable for CoinbaseCommitment {
  type Error = CbTxInvalid;

  fn check(&self) -> Option<Self::Error> {
    if self.version == 0 || self.version >= 4 {
      return Some(CbTxInvalid::BadVersion { version: self.version });
    }

    // A non-canonical signature counts as a payload decode failure.
    if self.best_cl_signature.is_some_and(|sig| !sig.is_canonical()) {
      return Some(CbTxInvalid::BadPayload);
    }

    if self.version >= 2 {
      if self.merkle_root_quorums.is_none() {
        return Some(CbTxInvalid::MissingField);
      }
    } else if self.merkle_root_quorums.is_some() {
      return Some(CbTxInvalid::UnexpectedField);
    }

    if self.version >= 3 {
      if self.best_cl_height_diff.is_none() || self.best_cl_signature.is_none() || self.credit_pool_balance.is_none() {
        return Some(CbTxInvalid::MissingField);
      }
    } else if self.best_cl_height_diff.is_some()
      || self.best_cl_signature.is_some()
      || self.credit_pool_balance.is_some()
    {
      return Some(CbTxInvalid::UnexpectedField);
    }

    None
  }
}

hash_impl!(CoinbaseCommitment);

impl fmt::Display for CoinbaseCommitment {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "CoinbaseCommitment {{ v{}, height: {} }}", self.version, self.height)
  }
}

#[cfg(all(test, feature = "serde"))]
#[expect(clippy::unwrap_used, reason = "test code")]
mod tests {
  use super::*;
  use crate::prelude::*;

  use dash_dev::{assert_serde_rt, check_sptx, Corpus};
  use dash_types::MAX_SIZE;
  use rstest::rstest;

  fn v3_item() -> CoinbaseCommitment {
    let corpus = Corpus::open(env!("CARGO_MANIFEST_DIR"), "cbtx");
    corpus
      .entries::<CoinbaseCommitment>("cbtx", |_, _, _| {})
      .into_values()
      .find(|item| item.version == 3)
      .unwrap()
  }

  #[rstest]
  #[case::zero(0)]
  #[case::max_size(MAX_SIZE as u32)]
  fn height_diff_up_to_max_size_round_trips(#[case] diff: u32) {
    let mut item = v3_item();
    item.best_cl_height_diff = Some(diff);
    let mut buf = Vec::new();
    item.encode(&mut buf);
    assert_eq!(CoinbaseCommitment::decode(&mut buf.as_slice()), Ok(item));
  }

  #[rstest]
  #[case::past_max_size(MAX_SIZE as u32 + 1)]
  #[case::u32_max(u32::MAX)]
  fn height_diff_past_max_size_is_rejected(#[case] diff: u32) {
    let mut item = v3_item();
    item.best_cl_height_diff = Some(diff);
    let mut buf = Vec::new();
    item.encode(&mut buf);
    assert_eq!(
      CoinbaseCommitment::decode(&mut buf.as_slice()),
      Err(DecodeError::CompactSizeExceedsLimit {
        limit: MAX_SIZE as usize,
        value: u64::from(diff),
      })
    );
  }

  /// A diff past `u32::MAX` meets the range check before the type bound, so
  /// the error names `MAX_SIZE`.
  #[rstest]
  fn height_diff_past_u32_reports_max_size() {
    let mut item = v3_item();
    item.best_cl_height_diff = Some(0);
    let mut buf = Vec::new();
    item.encode(&mut buf);
    // The diff sits after the version, height and two merkle roots.
    let offset = 2 + 4 + 32 + 32;
    let mut wire = buf[..offset].to_vec();
    CompactSize::new(u64::from(u32::MAX) + 1).encode(&mut wire);
    wire.extend(buf[offset + 1..].iter().copied());
    assert_eq!(
      CoinbaseCommitment::decode(&mut wire.as_slice()),
      Err(DecodeError::CompactSizeExceedsLimit {
        limit: MAX_SIZE as usize,
        value: u64::from(u32::MAX) + 1,
      })
    );
  }

  #[rstest]
  fn corpus_cbtx() {
    let corpus = Corpus::open(env!("CARGO_MANIFEST_DIR"), "cbtx");
    let items = corpus.entries::<CoinbaseCommitment>("cbtx", check_sptx);
    assert_serde_rt("cbtx", &items);
  }

  #[rstest]
  fn signature_is_basic() {
    let corpus = Corpus::open(env!("CARGO_MANIFEST_DIR"), "cbtx");
    for (label, item) in corpus.entries::<CoinbaseCommitment>("cbtx", |_, _, _| {}) {
      assert_eq!(
        item.best_cl_signature.map(|sig| sig.scheme()),
        (item.version >= 3).then_some(BlsScheme::Basic),
        "{label}"
      );
    }
  }
  #[rstest]
  fn non_canonical_signature_is_a_bad_payload() {
    let corpus = Corpus::open(env!("CARGO_MANIFEST_DIR"), "cbtx");
    let mut item = corpus
      .entries::<CoinbaseCommitment>("cbtx", |_, _, _| {})
      .into_values()
      .find(|item| item.best_cl_signature.is_some())
      .unwrap();
    assert_eq!(item.check(), None);
    item.best_cl_signature = item.best_cl_signature.map(|sig| sig.corrupted());
    assert_eq!(item.check(), Some(CbTxInvalid::BadPayload));
    assert_eq!(CbTxInvalid::BadPayload.to_string(), "bad-cbtx-payload");
  }
}
