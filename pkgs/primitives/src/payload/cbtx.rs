//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! CoinbaseCommitment coinbase commitment payload (type 5).

use crate::codec::impl_payload;
use crate::deployment::{Activation, Deployments};
use crate::types::{BlsScheme, BlsSig};
use crate::{hash_impl, MerkleRoot};

use bitcoin_units::BlockHeight;
use dash_pkc::bls::{BlsScIetf, BlsSigBytes, BLS_SIG_LEN};
use dash_types::codec::{BaseCodec, DecodeError, EncodeBuf};
use dash_types::type_id::{TypeId, Unencodable};
use dash_types::{Checkable, CompactSize};

use core::fmt;

/// CoinbaseCommitment -- coinbase commitment payload.
///
/// - v1: base fields (version, height, merkle_root_mn_list)
/// - v2: adds merkle_root_quorums
/// - v3: adds ChainLock proof and credit pool balance
/// - v4: adds merkle_root_asset_unlocks
///
/// The version-gated fields are private, so [`CoinbaseCommitment::new`]
/// keeps them in step with the version.
#[derive(Clone, Debug, Eq, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase", try_from = "__CbTxFields"))]
pub struct CoinbaseCommitment {
  version: u16,
  /// Block height.
  pub height: BlockHeight,
  /// Merkle root of the masternode list.
  pub merkle_root_mn_list: MerkleRoot,
  merkle_root_quorums: Option<MerkleRoot>,
  best_cl_height_diff: Option<u32>,
  best_cl_signature: Option<BlsSig>,
  credit_pool_balance: Option<i64>,
  merkle_root_asset_unlocks: Option<MerkleRoot>,
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
    let merkle_root_asset_unlocks = if version >= 4 {
      Some(MerkleRoot::decode(data)?)
    } else {
      None
    };

    Ok(Self {
      version,
      height,
      merkle_root_mn_list,
      merkle_root_quorums,
      best_cl_height_diff,
      best_cl_signature,
      credit_pool_balance,
      merkle_root_asset_unlocks,
    })
  }

  fn encode(&self, buf: &mut impl EncodeBuf) {
    self.version.encode(buf);
    self.height.to_u32().encode(buf);
    self.merkle_root_mn_list.encode(buf);
    if let Some(root) = self.merkle_root_quorums {
      root.encode(buf);
    }
    if let Some(diff) = self.best_cl_height_diff {
      CompactSize::from(u64::from(diff)).encode(buf);
    }
    if let Some(sig) = self.best_cl_signature {
      sig.encode(buf);
    }
    if let Some(balance) = self.credit_pool_balance {
      balance.encode(buf);
    }
    if let Some(root) = self.merkle_root_asset_unlocks {
      root.encode(buf);
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
  /// `bad-cbtx-cldiff`
  BadClHeightDiff { diff: u32 },
}

impl core::fmt::Display for CbTxInvalid {
  fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
    match self {
      Self::BadVersion { version } => write!(f, "bad-cbtx-version: {version}"),
      Self::MissingField => write!(f, "bad-cbtx-missing-field"),
      Self::UnexpectedField => write!(f, "bad-cbtx-unexpected-field"),
      Self::BadPayload => write!(f, "bad-cbtx-payload"),
      Self::BadClHeightDiff { diff } => write!(f, "bad-cbtx-cldiff: {diff}"),
    }
  }
}

impl Checkable for CoinbaseCommitment {
  type Error = CbTxInvalid;

  fn check(&self) -> Option<Self::Error> {
    if self.version == 0 || self.version >= 5 {
      return Some(CbTxInvalid::BadVersion { version: self.version });
    }

    // A non-canonical signature counts as a payload decode failure.
    if self.best_cl_signature.is_some_and(|sig| !sig.is_canonical()) {
      return Some(CbTxInvalid::BadPayload);
    }

    if let Some(error) = self.check_fields() {
      return Some(error);
    }

    // The payload height stands in for the block height, which it equals in
    // any block that passes `bad-cbtx-height`.
    match (self.best_cl_signature, self.best_cl_height_diff) {
      (Some(sig), Some(diff)) if sig.is_null() && diff != 0 => Some(CbTxInvalid::BadClHeightDiff { diff }),
      (Some(sig), Some(diff)) if !sig.is_null() && diff >= self.height.to_u32() => {
        Some(CbTxInvalid::BadClHeightDiff { diff })
      }
      _ => None,
    }
  }
}

hash_impl!(CoinbaseCommitment);

impl CoinbaseCommitment {
  /// Builds a commitment whose optional fields are present exactly at the
  /// versions that carry them. The signature takes the basic scheme.
  ///
  /// # Errors
  ///
  /// Returns [`CbTxInvalid::MissingField`] or [`CbTxInvalid::UnexpectedField`]
  /// when a field does not match `version`.
  #[expect(clippy::too_many_arguments, reason = "one argument per payload field")]
  pub fn new(
    version: u16,
    height: BlockHeight,
    merkle_root_mn_list: MerkleRoot,
    merkle_root_quorums: Option<MerkleRoot>,
    best_cl_height_diff: Option<u32>,
    best_cl_signature: Option<[u8; BLS_SIG_LEN]>,
    credit_pool_balance: Option<i64>,
    merkle_root_asset_unlocks: Option<MerkleRoot>,
  ) -> Result<Self, CbTxInvalid> {
    let cbtx = Self {
      version,
      height,
      merkle_root_mn_list,
      merkle_root_quorums,
      best_cl_height_diff,
      best_cl_signature: best_cl_signature.map(|sig| BlsSig::from_bytes(sig, BlsScheme::Basic)),
      credit_pool_balance,
      merkle_root_asset_unlocks,
    };
    match cbtx.check_fields() {
      Some(error) => Err(error),
      None => Ok(cbtx),
    }
  }

  /// Payload version.
  pub const fn version(&self) -> u16 {
    self.version
  }

  /// Merkle root of quorum commitments, carried from version 2.
  pub const fn merkle_root_quorums(&self) -> Option<MerkleRoot> {
    self.merkle_root_quorums
  }

  /// Best ChainLock height difference, carried from version 3. The wire
  /// form is at most [`dash_types::MAX_SIZE`].
  pub const fn best_cl_height_diff(&self) -> Option<u32> {
    self.best_cl_height_diff
  }

  /// Best ChainLock signature, carried from version 3 in the basic scheme.
  pub const fn best_cl_signature(&self) -> Option<BlsSig> {
    self.best_cl_signature
  }

  /// Credit pool balance in duffs, carried from version 3.
  pub const fn credit_pool_balance(&self) -> Option<i64> {
    self.credit_pool_balance
  }

  /// Merkle root of the instance hashes of the block's asset unlocks with a
  /// stable txid, carried from version 4. A block without such unlocks
  /// commits to the null root.
  pub const fn merkle_root_asset_unlocks(&self) -> Option<MerkleRoot> {
    self.merkle_root_asset_unlocks
  }

  /// Height and signature of the best ChainLock the commitment carries, or
  /// `None` when it carries no valid one. A [`ChainLockSig`] needs the hash
  /// of the block at that height, which only the chain knows.
  ///
  /// [`ChainLockSig`]: crate::ChainLockSig
  pub fn best_chainlock(&self) -> Option<(i32, BlsSigBytes<BlsScIetf>)> {
    let sig = self
      .best_cl_signature
      .filter(|sig| !sig.is_null() && sig.is_canonical())?;
    // The payload height stands in for the block height, which it equals in
    // any block that passes `bad-cbtx-height`.
    let block_height = i32::try_from(self.height.to_u32()).ok()?;
    let diff = i32::try_from(self.best_cl_height_diff?).ok()?;
    (diff < block_height).then(|| (block_height - diff - 1, BlsSigBytes::from_bytes(*sig.as_bytes())))
  }

  /// Requires version 4 once v20 and v24 are both active, and rejects it
  /// otherwise.
  pub fn check_deployments(&self, deployments: Deployments) -> Option<CbTxInvalid> {
    let requires_unlock_root = deployments.v20 == Activation::Active && deployments.v24 == Activation::Active;
    (requires_unlock_root != (self.version >= 4)).then_some(CbTxInvalid::BadVersion { version: self.version })
  }

  const fn check_fields(&self) -> Option<CbTxInvalid> {
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

    if self.version >= 4 {
      if self.merkle_root_asset_unlocks.is_none() {
        return Some(CbTxInvalid::MissingField);
      }
    } else if self.merkle_root_asset_unlocks.is_some() {
      return Some(CbTxInvalid::UnexpectedField);
    }

    None
  }
}

/// Field set that builds a deserialized commitment through
/// [`CoinbaseCommitment::new`].
#[cfg(feature = "serde")]
#[derive(::serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct __CbTxFields {
  version: u16,
  height: BlockHeight,
  merkle_root_mn_list: MerkleRoot,
  merkle_root_quorums: Option<MerkleRoot>,
  best_cl_height_diff: Option<u32>,
  #[serde(default, deserialize_with = "crate::serialize::bls::sig_basic_opt")]
  best_cl_signature: Option<BlsSig>,
  credit_pool_balance: Option<i64>,
  merkle_root_asset_unlocks: Option<MerkleRoot>,
}

#[cfg(feature = "serde")]
impl TryFrom<__CbTxFields> for CoinbaseCommitment {
  type Error = CbTxInvalid;

  fn try_from(fields: __CbTxFields) -> Result<Self, Self::Error> {
    Self::new(
      fields.version,
      fields.height,
      fields.merkle_root_mn_list,
      fields.merkle_root_quorums,
      fields.best_cl_height_diff,
      fields.best_cl_signature.map(|sig| *sig.as_bytes()),
      fields.credit_pool_balance,
      fields.merkle_root_asset_unlocks,
    )
  }
}

impl fmt::Display for CoinbaseCommitment {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "CoinbaseCommitment {{ v{}, height: {} }}", self.version, self.height)
  }
}

#[cfg(all(test, feature = "serde"))]
mod tests {
  use super::*;
  use crate::prelude::*;

  use dash_dev::{assert_serde_rt, check_sptx, from_json, json_rejects, to_json, Corpus};
  use dash_types::Numeric;
  use dash_types::MAX_SIZE;
  use rstest::rstest;

  fn v3_item() -> CoinbaseCommitment {
    let corpus = Corpus::open(env!("CARGO_MANIFEST_DIR"), "cbtx");
    corpus
      .entries::<CoinbaseCommitment>("cbtx", |_, _, _| {})
      .into_values()
      .filter(|item| item.version == 3)
      .collect::<Vec<_>>()
      .swap_remove(0)
  }

  fn sig() -> [u8; BLS_SIG_LEN] {
    [0; BLS_SIG_LEN]
  }

  fn build(
    version: u16,
    quorums: Option<MerkleRoot>,
    diff: Option<u32>,
    sig: Option<[u8; BLS_SIG_LEN]>,
    balance: Option<i64>,
    unlocks: Option<MerkleRoot>,
  ) -> Result<CoinbaseCommitment, CbTxInvalid> {
    let root = MerkleRoot::from_lendian([0x22; 32]);
    CoinbaseCommitment::new(
      version,
      BlockHeight::from_u32(7),
      root,
      quorums,
      diff,
      sig,
      balance,
      unlocks,
    )
  }

  fn quorums() -> Option<MerkleRoot> {
    Some(MerkleRoot::from_lendian([0x33; 32]))
  }

  fn unlocks() -> Option<MerkleRoot> {
    Some(MerkleRoot::from_lendian([0x44; 32]))
  }

  #[rstest]
  fn best_chainlock_sits_below_the_parent() {
    let item = v3_item();
    let expected = item.best_cl_signature.zip(item.best_cl_height_diff).map(|(sig, diff)| {
      let height = item.height.to_u32() - diff - 1;
      (height as i32, BlsSigBytes::from_bytes(*sig.as_bytes()))
    });
    assert!(expected.is_some());
    assert_eq!(item.best_chainlock(), expected);
  }

  #[rstest]
  #[case::diff_below_height(6, Some(0))]
  #[case::diff_at_height(7, None)]
  #[case::diff_past_height(8, None)]
  #[case::diff_past_i32(u32::MAX, None)]
  fn best_chainlock_needs_a_diff_below_the_height(#[case] diff: u32, #[case] expected: Option<i32>) {
    let mut item = v3_item();
    item.height = BlockHeight::from_u32(7);
    item.best_cl_height_diff = Some(diff);
    assert_eq!(item.best_chainlock().map(|(height, _)| height), expected);
  }

  #[rstest]
  fn best_chainlock_needs_a_valid_signature() {
    let mut item = v3_item();
    item.best_cl_signature = item.best_cl_signature.map(|sig| sig.corrupted());
    assert_eq!(item.best_chainlock(), None);
    item.best_cl_signature = Some(BlsSig::from_bytes(sig(), BlsScheme::Basic));
    assert_eq!(item.best_chainlock(), None);
  }

  #[rstest]
  fn best_chainlock_needs_version_3() -> Result<(), CbTxInvalid> {
    assert_eq!(build(2, quorums(), None, None, None, None)?.best_chainlock(), None);
    Ok(())
  }

  #[rstest]
  #[case::v0(0, true)]
  #[case::v4(4, false)]
  #[case::v5(5, true)]
  fn versions_1_to_4_are_known(#[case] version: u16, #[case] rejected: bool) {
    let mut item = v3_item();
    item.version = version;
    item.merkle_root_asset_unlocks = (version >= 4).then(|| MerkleRoot::from_lendian([0x44; 32]));
    assert_eq!(item.check(), rejected.then_some(CbTxInvalid::BadVersion { version }));
  }

  #[rstest]
  #[case::v1(1, None, None, None, None, None)]
  #[case::v2(2, quorums(), None, None, None, None)]
  #[case::v3(3, quorums(), Some(0), Some(sig()), Some(-7), None)]
  #[case::v4(4, quorums(), Some(0), Some(sig()), Some(-7), unlocks())]
  fn consistent_fields_build_and_round_trip(
    #[case] version: u16,
    #[case] quorums: Option<MerkleRoot>,
    #[case] diff: Option<u32>,
    #[case] sig: Option<[u8; BLS_SIG_LEN]>,
    #[case] balance: Option<i64>,
    #[case] unlocks: Option<MerkleRoot>,
  ) -> Result<(), CbTxInvalid> {
    let cbtx = build(version, quorums, diff, sig, balance, unlocks)?;
    assert_eq!(
      (
        cbtx.version(),
        cbtx.merkle_root_quorums(),
        cbtx.best_cl_height_diff(),
        cbtx.best_cl_signature(),
        cbtx.credit_pool_balance(),
        cbtx.merkle_root_asset_unlocks()
      ),
      (
        version,
        quorums,
        diff,
        sig.map(|sig| BlsSig::from_bytes(sig, BlsScheme::Basic)),
        balance,
        unlocks
      )
    );
    assert_eq!(cbtx.check(), None);

    let mut buf = Vec::new();
    cbtx.encode(&mut buf);
    let mut cursor = buf.as_slice();
    assert_eq!(CoinbaseCommitment::decode(&mut cursor), Ok(cbtx.clone()));
    assert!(cursor.is_empty());
    assert_eq!(from_json::<CoinbaseCommitment>(&to_json(&cbtx)), cbtx);
    Ok(())
  }

  #[rstest]
  #[case::v2_without_quorums(build(2, None, None, None, None, None), CbTxInvalid::MissingField)]
  #[case::v3_without_quorums(build(3, None, Some(5), Some(sig()), Some(1), None), CbTxInvalid::MissingField)]
  #[case::v3_without_diff(build(3, quorums(), None, Some(sig()), Some(1), None), CbTxInvalid::MissingField)]
  #[case::v3_without_sig(build(3, quorums(), Some(5), None, Some(1), None), CbTxInvalid::MissingField)]
  #[case::v3_without_balance(build(3, quorums(), Some(5), Some(sig()), None, None), CbTxInvalid::MissingField)]
  #[case::v1_with_quorums(build(1, quorums(), None, None, None, None), CbTxInvalid::UnexpectedField)]
  #[case::v2_with_diff(build(2, quorums(), Some(5), None, None, None), CbTxInvalid::UnexpectedField)]
  #[case::v2_with_sig(build(2, quorums(), None, Some(sig()), None, None), CbTxInvalid::UnexpectedField)]
  #[case::v2_with_balance(build(2, quorums(), None, None, Some(1), None), CbTxInvalid::UnexpectedField)]
  #[case::v4_without_unlocks(build(4, quorums(), Some(5), Some(sig()), Some(1), None), CbTxInvalid::MissingField)]
  #[case::v3_with_unlocks(
    build(3, quorums(), Some(5), Some(sig()), Some(1), unlocks()),
    CbTxInvalid::UnexpectedField
  )]
  fn inconsistent_fields_do_not_build(
    #[case] built: Result<CoinbaseCommitment, CbTxInvalid>,
    #[case] error: CbTxInvalid,
  ) {
    assert_eq!(built, Err(error));
  }

  #[rstest]
  fn deserialization_goes_through_new() -> Result<(), CbTxInvalid> {
    let v2 = build(2, quorums(), None, None, None, None)?;
    let json = to_json(&v2).replace("\"version\":2", "\"version\":3");
    assert!(json_rejects::<CoinbaseCommitment>(&json));
    Ok(())
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
  #[case::zero(0, None)]
  #[case::one(1, Some(CbTxInvalid::BadClHeightDiff { diff: 1 }))]
  fn null_chainlock_needs_a_zero_height_diff(#[case] diff: u32, #[case] expected: Option<CbTxInvalid>) {
    let mut item = v3_item();
    item.best_cl_signature = Some(BlsSig::from_bytes([0; BLS_SIG_LEN], BlsScheme::Basic));
    item.best_cl_height_diff = Some(diff);
    assert_eq!(item.check(), expected);
    assert_eq!(
      CbTxInvalid::BadClHeightDiff { diff: 1 }.to_string(),
      "bad-cbtx-cldiff: 1"
    );
  }

  #[rstest]
  #[case::below_the_height(6, None)]
  #[case::at_the_height(7, Some(CbTxInvalid::BadClHeightDiff { diff: 7 }))]
  #[case::above_the_height(8, Some(CbTxInvalid::BadClHeightDiff { diff: 8 }))]
  fn chainlock_height_diff_stays_below_the_height(#[case] diff: u32, #[case] expected: Option<CbTxInvalid>) {
    let mut item = v3_item();
    assert!(item.best_cl_signature.is_some_and(|sig| !sig.is_null()));
    item.height = BlockHeight::from_u32(7);
    item.best_cl_height_diff = Some(diff);
    assert_eq!(item.check(), expected);
  }

  #[rstest]
  #[case::v3_before_v24(3, Activation::Active, Activation::Inactive, None)]
  #[case::v4_before_v24(4, Activation::Active, Activation::Inactive, Some(CbTxInvalid::BadVersion { version: 4 }))]
  #[case::v3_under_v24(3, Activation::Active, Activation::Active, Some(CbTxInvalid::BadVersion { version: 3 }))]
  #[case::v4_under_v24(4, Activation::Active, Activation::Active, None)]
  #[case::v4_under_v24_alone(4, Activation::Inactive, Activation::Active, Some(CbTxInvalid::BadVersion { version: 4 }))]
  fn version_4_follows_v20_and_v24(
    #[case] version: u16,
    #[case] v20: Activation,
    #[case] v24: Activation,
    #[case] expected: Option<CbTxInvalid>,
  ) {
    let mut item = v3_item();
    item.version = version;
    let deployments = Deployments {
      v19: Activation::Active,
      v20,
      v24,
      evo_shares: Activation::Inactive,
    };
    assert_eq!(item.check_deployments(deployments), expected);
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
      .filter(|item| item.best_cl_signature.is_some())
      .collect::<Vec<_>>()
      .swap_remove(0);
    assert_eq!(item.check(), None);
    item.best_cl_signature = item.best_cl_signature.map(|sig| sig.corrupted());
    assert_eq!(item.check(), Some(CbTxInvalid::BadPayload));
    assert_eq!(CbTxInvalid::BadPayload.to_string(), "bad-cbtx-payload");
  }
}
