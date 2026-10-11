//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Special transaction payload decoders.
//!
//! Each payload type is decoded from the `extra_payload` field of a
//! `Transaction` whose `tx_type` is not `Spend`.

mod assetlock;
mod assetunlock;
mod cbtx;
mod mnhftx;
mod prodistx;
mod proregtx;
mod protx;
mod proupregtx;
mod prouprevtx;
mod proupservtx;
mod proupsharedregtx;
mod proupsharetx;
mod quorum;

use crate::hash_impl;
use crate::prelude::*;
use crate::types::{NIError, NIPurpose, NITrait, NetAddrError, NetInfo, NetInfoV2};

use bitcoin_units::Amount;
use dash_num::{make_hash, Hash256};
use dash_types::codec::{BaseCodec, DecodeError, EncodeBuf};
use dash_types::type_id::{TypeId, Unencodable};
use dash_types::Numeric;
use dash_types::{enum_map, impl_num, Checkable};

use core::fmt;

pub use self::assetlock::{AssetLock, AssetLockInvalid};
pub use self::assetunlock::{
  AssetUnlock, AssetUnlockInvalid, ASSET_UNLOCK_PAYLOAD_SIZE, ASSET_UNLOCK_QUORUM_INFO_SIZE,
  ASSET_UNLOCK_STABLE_TXID_VERSION, MAXIMUM_WITHDRAWALS,
};
pub use self::cbtx::{CbTxInvalid, CoinbaseCommitment};
pub use self::mnhftx::{MnHardFork, MnHardForkInvalid, VERSIONBITS_NUM_BITS};
pub use self::prodistx::ProDisTx;
pub use self::proregtx::ProRegTx;
pub use self::protx::{CollateralShare, CompactSignature, MasternodePayoutShare};
pub use self::proupregtx::ProUpRegTx;
pub use self::prouprevtx::ProUpRevTx;
pub use self::proupservtx::ProUpServTx;
pub use self::proupsharedregtx::ProUpSharedRegTx;
pub use self::proupsharetx::ProUpShareTx;
pub use self::quorum::{Commitment, CommitmentFault, CommitmentInvalid, FinalCommitment, QuorumVvecHash};

pub use dash_pkc::__private::__EddsaPkHash as PlatformNodeId;

/// Maximum operator reward in basis points.
pub(crate) const MAX_OPERATOR_REWARD: u16 = 10_000;

/// ProTx version: legacy BLS operator keys (v1).
pub const PROTX_VERSION_LEGACY_BLS: u16 = 1;

/// ProTx version: basic (IETF) BLS operator keys (v2).
pub const PROTX_VERSION_BASIC_BLS: u16 = 2;

/// ProTx version: extended network addresses (v3).
pub const PROTX_VERSION_EXT_ADDR: u16 = 3;

make_hash! {
  /// LLMQ quorum identifier.
  QuorumHash, 32
}

hash_impl!(QuorumHash);

make_hash! {
  /// Hash of serialized transaction inputs.
  InputsHash, 32
}

hash_impl!(InputsHash);

make_hash! {
  /// Hash of serialized transaction outputs.
  OutputsHash, 32
}

hash_impl!(OutputsHash);

enum_map! {
  /// Dash transaction type, encoded in the upper 16 bits of the version field.
  #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, TypeId)]
  pub enum TxType, u16, Unknown {
    /// Spend transaction (includes legacy coinbase).
    Spend = 0 => "spend",
    /// Masternode registration (type 1).
    ProviderRegister = 1 => "provider_register",
    /// Masternode service address update (type 2).
    ProviderUpdateService = 2 => "provider_update_service",
    /// Masternode registrar key update (type 3).
    ProviderUpdateRegistrar = 3 => "provider_update_registrar",
    /// Masternode revocation (type 4).
    ProviderUpdateRevoke = 4 => "provider_update_revoke",
    /// Coinbase commitment special transaction (type 5).
    CoinbaseCommitment = 5 => "coinbase_commitment",
    /// LLMQ final commitment (type 6).
    QuorumCommitment = 6 => "quorum_commitment",
    /// Masternode hard fork signal (type 7).
    MnhfSignal = 7 => "mnhf_signal",
    /// Asset lock: L1 to platform (type 8).
    AssetLock = 8 => "asset_lock",
    /// Asset unlock: platform to L1 (type 9).
    AssetUnlock = 9 => "asset_unlock",
    /// Shared masternode dissolution (type 10).
    ProviderDissolve = 10 => "provider_dissolve",
    /// Collateral share reward update (type 11).
    ProviderUpdateShare = 11 => "provider_update_share",
    /// Shared masternode registrar key update (type 12).
    ProviderUpdateSharedRegistrar = 12 => "provider_update_shared_registrar",
  }
}

impl_num!(TxType, u16);

hash_impl!(TxType);

enum_map! {
  /// Masternode type, used in provider registration and update transactions.
  #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, TypeId)]
  pub enum MnType, u16, Unknown {
    /// Regular masternode.
    Regular = 0 => "regular",
    /// Evolution (Evo) masternode with platform capabilities.
    Evo = 1 => "evo",
  }
}

impl_num!(MnType, u16);

hash_impl!(MnType);

impl MnType {
  /// Collateral a masternode of this type locks, or `None` for an unknown
  /// type.
  pub const fn collateral_amount(self) -> Option<Amount> {
    match self {
      Self::Regular => Some(Amount::from_btc_u16(1000)),
      Self::Evo => Some(Amount::from_btc_u16(4000)),
      Self::Unknown(_) => None,
    }
  }
}

/// Provider transaction validation failure.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Unencodable)]
pub enum ProTxInvalid {
  /// `bad-protx-version`
  BadVersion { version: u16 },
  /// `bad-protx-evo-version`
  EvoVersionTooLow { version: u16 },
  /// `bad-protx-type`
  BadMnType { mn_type: MnType },
  /// `bad-protx-mode`
  BadMode { mode: u16 },
  /// `bad-protx-key-null`
  NullKey,
  /// `bad-protx-operator-pubkey`
  OperatorKeyMismatch,
  /// `bad-protx-payee`
  BadPayoutScript,
  /// `bad-protx-payouts-count`
  BadPayoutCount { count: usize },
  /// `bad-protx-payout-reward`
  BadPayoutReward { reward: u16 },
  /// `bad-protx-payee-dup`
  DuplicatePayoutScript,
  /// `bad-protx-payout-reward-sum`
  BadPayoutRewardSum { total: u32 },
  /// `bad-protx-shares-external`
  SharesExternal,
  /// `bad-protx-shares-owner-key`
  SharesOwnerKey,
  /// `bad-protx-shares-payouts`
  SharesPayouts,
  /// `bad-protx-shares-empty-fields`
  SharesEmptyFields,
  /// `bad-protx-shares-count`
  BadShareCount { count: usize },
  /// `bad-protx-shares-early-period`
  BadEarlyPeriod { blocks: u32 },
  /// `bad-protx-shares-amount`
  BadShareAmount { amount: i64 },
  /// `bad-protx-shares-key-null`
  NullShareKey,
  /// `bad-protx-shares-dup-key`
  DuplicateShareKey,
  /// `bad-protx-shares-dup-refund`
  DuplicateShareRefund,
  /// `bad-protx-shares-payee`
  BadSharePayee,
  /// `bad-protx-shares-payee-reuse`
  SharePayeeReuse,
  /// `bad-protx-shares-amount-sum`
  BadShareAmountSum { total: i64 },
  /// `bad-protx-shares-penalty`
  BadSharePenalty { penalty: i64 },
  /// `bad-protx-netinfo-version`
  NetInfoVersionMismatch,
  /// `bad-protx-netinfo-empty`
  NetInfoEmpty,
  /// `bad-protx-netinfo-addr`, `-port`, `-addr-type`, `-addr-unroutable`,
  /// `-maxlimit`, `-bad` or `bad-protx-dup-netinfo-entry`, by the kind of
  /// `error`
  NetInfoInvalid {
    /// The underlying error.
    error: NIError,
  },
  /// `bad-protx-payee-reuse`
  PayoutKeyReuse,
  /// `bad-protx-operator-reward`
  OperatorRewardTooHigh { reward: u16 },
  /// `bad-protx-reason`
  BadReason { reason: crate::support::RevocationReason },
  /// `bad-protx-platform-fields`
  BadPlatformFields,
  /// `bad-protx-payout-fields`
  BadPayoutFields,
  /// `bad-protx-payload`
  BadPayload,
  /// `bad-protx-operator-payee`
  BadOperatorPayoutScript,
  /// `bad-protx-platform-nodeid`
  NullPlatformNodeId,
  /// `bad-protx-platform-p2p-port`
  BadPlatformP2pPort { port: u16 },
  /// `bad-protx-platform-http-port`
  BadPlatformHttpPort { port: u16 },
  /// `bad-protx-platform-dup-ports`
  DuplicatePlatformPorts,
  /// `bad-protx-inputs-hash`
  BadInputsHash,
  /// `bad-prodis-version`
  BadDissolveVersion { version: u16 },
  /// `bad-prodis-sig-count`
  BadDissolveSigCount { count: usize },
  /// `bad-proupsharedreg-sig-count`
  BadSharedRegSigCount { count: usize },
  /// `bad-proupshare-version`
  BadShareUpdateVersion { version: u16 },
  /// `bad-proupshare-sig-size`
  BadShareUpdateSigSize { size: usize },
  /// `bad-proupshare-payee`
  BadShareUpdatePayee,
  /// `bad-proupsharedreg-version`
  BadSharedRegVersion { version: u16 },
  /// `bad-protx-shares-collateral-script`
  SharesCollateralScript,
}

impl fmt::Display for ProTxInvalid {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    match self {
      Self::BadVersion { version } => write!(f, "bad-protx-version: {version}"),
      Self::EvoVersionTooLow { version } => write!(f, "bad-protx-evo-version: {version}"),
      Self::BadMnType { mn_type } => write!(f, "bad-protx-type: {mn_type}"),
      Self::BadMode { mode } => write!(f, "bad-protx-mode: {mode}"),
      Self::NullKey => write!(f, "bad-protx-key-null"),
      Self::OperatorKeyMismatch => write!(f, "bad-protx-operator-pubkey"),
      Self::BadPayoutScript => write!(f, "bad-protx-payee"),
      Self::BadPayoutCount { count } => write!(f, "bad-protx-payouts-count: {count}"),
      Self::BadPayoutReward { reward } => write!(f, "bad-protx-payout-reward: {reward}"),
      Self::DuplicatePayoutScript => write!(f, "bad-protx-payee-dup"),
      Self::BadPayoutRewardSum { total } => write!(f, "bad-protx-payout-reward-sum: {total}"),
      Self::SharesExternal => write!(f, "bad-protx-shares-external"),
      Self::SharesOwnerKey => write!(f, "bad-protx-shares-owner-key"),
      Self::SharesPayouts => write!(f, "bad-protx-shares-payouts"),
      Self::SharesEmptyFields => write!(f, "bad-protx-shares-empty-fields"),
      Self::BadShareCount { count } => write!(f, "bad-protx-shares-count: {count}"),
      Self::BadEarlyPeriod { blocks } => write!(f, "bad-protx-shares-early-period: {blocks}"),
      Self::BadShareAmount { amount } => write!(f, "bad-protx-shares-amount: {amount}"),
      Self::NullShareKey => write!(f, "bad-protx-shares-key-null"),
      Self::DuplicateShareKey => write!(f, "bad-protx-shares-dup-key"),
      Self::DuplicateShareRefund => write!(f, "bad-protx-shares-dup-refund"),
      Self::BadSharePayee => write!(f, "bad-protx-shares-payee"),
      Self::SharePayeeReuse => write!(f, "bad-protx-shares-payee-reuse"),
      Self::BadShareAmountSum { total } => write!(f, "bad-protx-shares-amount-sum: {total}"),
      Self::BadSharePenalty { penalty } => write!(f, "bad-protx-shares-penalty: {penalty}"),
      Self::NetInfoVersionMismatch => write!(f, "bad-protx-netinfo-version"),
      Self::NetInfoEmpty => write!(f, "bad-protx-netinfo-empty"),
      Self::NetInfoInvalid { error } => {
        let reason = match error {
          NIError::BadAddr {
            error: NetAddrError::BadPort { .. },
          }
          | NIError::BadPort { .. } => "bad-protx-netinfo-port",
          NIError::BadAddr { .. } => "bad-protx-netinfo-addr",
          NIError::BadType { .. } => "bad-protx-netinfo-addr-type",
          NIError::Duplicate => "bad-protx-dup-netinfo-entry",
          NIError::MaxLimit { .. } => "bad-protx-netinfo-maxlimit",
          NIError::Malformed => "bad-protx-netinfo-bad",
          NIError::NotRoutable => "bad-protx-netinfo-addr-unroutable",
        };
        write!(f, "{reason}: {error}")
      }
      Self::PayoutKeyReuse => write!(f, "bad-protx-payee-reuse"),
      Self::OperatorRewardTooHigh { reward } => write!(f, "bad-protx-operator-reward: {reward}"),
      Self::BadReason { reason } => write!(f, "bad-protx-reason: {reason}"),
      Self::BadPlatformFields => write!(f, "bad-protx-platform-fields"),
      Self::BadPayoutFields => write!(f, "bad-protx-payout-fields"),
      Self::BadPayload => write!(f, "bad-protx-payload"),
      Self::BadOperatorPayoutScript => write!(f, "bad-protx-operator-payee"),
      Self::NullPlatformNodeId => write!(f, "bad-protx-platform-nodeid"),
      Self::BadPlatformP2pPort { port } => write!(f, "bad-protx-platform-p2p-port: {port}"),
      Self::BadPlatformHttpPort { port } => write!(f, "bad-protx-platform-http-port: {port}"),
      Self::DuplicatePlatformPorts => write!(f, "bad-protx-platform-dup-ports"),
      Self::BadInputsHash => write!(f, "bad-protx-inputs-hash"),
      Self::BadDissolveVersion { version } => write!(f, "bad-prodis-version: {version}"),
      Self::BadDissolveSigCount { count } => write!(f, "bad-prodis-sig-count: {count}"),
      Self::BadSharedRegSigCount { count } => write!(f, "bad-proupsharedreg-sig-count: {count}"),
      Self::BadShareUpdateVersion { version } => write!(f, "bad-proupshare-version: {version}"),
      Self::BadShareUpdateSigSize { size } => write!(f, "bad-proupshare-sig-size: {size}"),
      Self::BadShareUpdatePayee => write!(f, "bad-proupshare-payee"),
      Self::BadSharedRegVersion { version } => write!(f, "bad-proupsharedreg-version: {version}"),
      Self::SharesCollateralScript => write!(f, "bad-protx-shares-collateral-script"),
    }
  }
}

/// A ProTx version of 0 or above [`PROTX_VERSION_EXT_ADDR`], after which a
/// payload holds nothing.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Unencodable)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(try_from = "u16", into = "u16"))]
pub struct UnknownProTxVersion(u16);

impl UnknownProTxVersion {
  /// Wraps `version`, or returns `None` for a version from 1 to
  /// [`PROTX_VERSION_EXT_ADDR`].
  pub const fn new(version: u16) -> Option<Self> {
    if version == 0 || version > PROTX_VERSION_EXT_ADDR {
      Some(Self(version))
    } else {
      None
    }
  }

  /// The version number.
  pub const fn version(&self) -> u16 {
    self.0
  }
}

impl TryFrom<u16> for UnknownProTxVersion {
  type Error = ProTxInvalid;

  fn try_from(version: u16) -> Result<Self, Self::Error> {
    Self::new(version).ok_or(ProTxInvalid::BadVersion { version })
  }
}

impl From<UnknownProTxVersion> for u16 {
  fn from(version: UnknownProTxVersion) -> Self {
    version.0
  }
}

/// A ProTx payload of types 1 to 4.
///
/// A payload of an unknown version carries only that version, so its fields
/// never hold placeholders.
#[derive(Clone, Debug, Eq, Hash, PartialEq, Unencodable)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(untagged))]
pub enum ProTxPayload<T> {
  /// A payload of a version from 1 to [`PROTX_VERSION_EXT_ADDR`].
  Known(T),
  /// A payload that ends after its version.
  UnknownVersion(UnknownProTxVersion),
}

impl<T: BaseCodec + Checkable<Error = ProTxInvalid>> ProTxPayload<T> {
  /// Reads a payload, stopping after the version when it is unknown.
  ///
  /// # Errors
  ///
  /// Returns the [`BaseCodec::decode`] error of `T` for a known version.
  pub fn decode(data: &mut &[u8]) -> Result<Self, DecodeError> {
    let mut rest = *data;
    match UnknownProTxVersion::new(u16::decode(&mut rest)?) {
      Some(version) => {
        *data = rest;
        Ok(Self::UnknownVersion(version))
      }
      None => T::decode(data).map(Self::Known),
    }
  }
}

impl<T: Checkable<Error = ProTxInvalid>> Checkable for ProTxPayload<T> {
  type Error = ProTxInvalid;

  fn check(&self) -> Option<Self::Error> {
    match self {
      Self::Known(payload) => payload.check(),
      Self::UnknownVersion(version) => Some(ProTxInvalid::BadVersion {
        version: version.version(),
      }),
    }
  }
}

/// Encoding of a ProTx payload's net info.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Unencodable)]
pub(crate) enum NetInfoForm {
  /// The bytes as decoded, which the txid covers.
  Wire,
  /// The canonical encoding, which the payload hash covers.
  Hash,
}

/// Writes `net_info` in `form`.
pub(crate) fn encode_net_info(net_info: &NetInfo, form: NetInfoForm, buf: &mut impl EncodeBuf) {
  match (form, net_info) {
    (NetInfoForm::Wire, NetInfo::Legacy(v1)) => v1.encode(buf),
    (NetInfoForm::Wire, NetInfo::Extended(v2)) => v2.encode(buf),
    (NetInfoForm::Hash, _) => net_info.encode_canonical(buf),
  }
}

/// Hashes the bytes `write` produces with SHA256d.
pub(crate) fn payload_hash(write: impl FnOnce(&mut Vec<u8>)) -> Hash256 {
  let mut buf = Vec::new();
  write(&mut buf);
  Hash256::from_lendian(bitcoin_hashes::sha256d::Hash::hash(&buf).to_byte_array())
}

/// Reads the version of a ProTx payload with fields.
///
/// # Errors
///
/// Returns [`DecodeError::InvalidValue`] for an unknown version, which only
/// [`ProTxPayload`] represents.
pub(crate) fn decode_version(data: &mut &[u8]) -> Result<u16, DecodeError> {
  let version = u16::decode(data)?;
  if UnknownProTxVersion::new(version).is_some() {
    return Err(DecodeError::InvalidValue {
      expected: (1..=PROTX_VERSION_EXT_ADDR).map(u64::from).collect(),
      actual: u64::from(version),
    });
  }
  Ok(version)
}

/// Checks that an extended net info payload is trivially valid.
pub(crate) fn check_sptx_netinfo(ext: &NetInfoV2, version: u16, mn_type: MnType) -> Option<ProTxInvalid> {
  if !ext.has_entries(NIPurpose::CoreP2p) {
    return Some(ProTxInvalid::NetInfoEmpty);
  }
  if mn_type == MnType::Regular
    && (ext.has_entries(NIPurpose::PlatformP2p) || ext.has_entries(NIPurpose::PlatformHttps))
  {
    return Some(ProTxInvalid::NetInfoInvalid {
      error: NIError::Malformed,
    });
  }
  if version >= PROTX_VERSION_EXT_ADDR
    && mn_type == MnType::Evo
    && (!ext.has_entries(NIPurpose::PlatformP2p) || !ext.has_entries(NIPurpose::PlatformHttps))
  {
    return Some(ProTxInvalid::NetInfoEmpty);
  }
  // The purpose checks precede validation of the entries themselves.
  ext.check().map(|error| ProTxInvalid::NetInfoInvalid { error })
}

/// A decoded special transaction payload.
///
/// Provides a unified dispatch over all Dash special transaction types. Unknown
/// or future types are stored as opaque bytes for forward compatibility.
#[derive(Clone, Debug, Eq, Hash, PartialEq, Unencodable)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub enum SpecialPayload {
  /// Masternode registration (type 1).
  ProviderRegister(ProTxPayload<ProRegTx>),
  /// Masternode service update (type 2).
  ProviderUpdateService(ProTxPayload<ProUpServTx>),
  /// Masternode registrar update (type 3).
  ProviderUpdateRegistrar(ProTxPayload<ProUpRegTx>),
  /// Masternode revocation (type 4).
  ProviderUpdateRevoke(ProTxPayload<ProUpRevTx>),
  /// Coinbase commitment (type 5).
  CoinbaseCommitment(CoinbaseCommitment),
  /// LLMQ final commitment (type 6).
  QuorumCommitment(FinalCommitment),
  /// Hard-fork signal (type 7).
  MnhfSignal(MnHardFork),
  /// Asset lock: L1 to Platform (type 8).
  AssetLock(AssetLock),
  /// Asset unlock: Platform to L1 (type 9).
  AssetUnlock(AssetUnlock),
  /// Shared masternode dissolution (type 10).
  ProviderDissolve(ProDisTx),
  /// Collateral share reward update (type 11).
  ProviderUpdateShare(ProUpShareTx),
  /// Shared masternode registrar key update (type 12).
  ProviderUpdateSharedRegistrar(ProUpSharedRegTx),
  /// Unrecognized type, stored as raw bytes.
  Unknown {
    /// The transaction type code.
    tx_type: TxType,
    /// The raw extra payload bytes.
    data: Vec<u8>,
  },
}

/// Error decoding a special payload.
#[derive(Clone, Debug, Eq, PartialEq, Hash, Unencodable)]
pub struct PayloadError {
  /// Which transaction type was being decoded.
  pub tx_type: TxType,
  /// Human-readable description.
  pub message: String,
}

impl fmt::Display for PayloadError {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "{} payload: {}", self.tx_type, self.message)
  }
}

/// Structural check failure for a special payload.
#[derive(Clone, Debug, Eq, PartialEq, Hash, Unencodable)]
pub enum PayloadInvalid {
  /// Provider transaction check failed.
  ProTx(ProTxInvalid),
  /// Coinbase commitment check failed.
  CbTx(CbTxInvalid),
  /// Hard-fork signal check failed.
  MnHardFork(MnHardForkInvalid),
  /// Asset lock check failed.
  AssetLock(AssetLockInvalid),
  /// Asset unlock check failed.
  AssetUnlock(AssetUnlockInvalid),
  /// Quorum commitment check failed.
  Commitment(CommitmentInvalid),
  /// Unrecognized special transaction.
  UnknownType(TxType),
}

impl fmt::Display for PayloadInvalid {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    match self {
      Self::ProTx(e) => e.fmt(f),
      Self::CbTx(e) => e.fmt(f),
      Self::MnHardFork(e) => e.fmt(f),
      Self::AssetLock(e) => e.fmt(f),
      Self::AssetUnlock(e) => e.fmt(f),
      Self::Commitment(e) => e.fmt(f),
      Self::UnknownType(t) => write!(f, "bad-txns-type: {t}"),
    }
  }
}

impl Checkable for SpecialPayload {
  type Error = PayloadInvalid;

  fn check(&self) -> Option<Self::Error> {
    match self {
      Self::ProviderRegister(p) => p.check().map(PayloadInvalid::ProTx),
      Self::ProviderUpdateService(p) => p.check().map(PayloadInvalid::ProTx),
      Self::ProviderUpdateRegistrar(p) => p.check().map(PayloadInvalid::ProTx),
      Self::ProviderUpdateRevoke(p) => p.check().map(PayloadInvalid::ProTx),
      Self::CoinbaseCommitment(p) => p.check().map(PayloadInvalid::CbTx),
      Self::QuorumCommitment(p) => p.check().map(PayloadInvalid::Commitment),
      Self::MnhfSignal(p) => p.check().map(PayloadInvalid::MnHardFork),
      Self::AssetLock(p) => p.check().map(PayloadInvalid::AssetLock),
      Self::AssetUnlock(p) => p.check().map(PayloadInvalid::AssetUnlock),
      Self::ProviderDissolve(p) => p.check().map(PayloadInvalid::ProTx),
      Self::ProviderUpdateShare(p) => p.check().map(PayloadInvalid::ProTx),
      Self::ProviderUpdateSharedRegistrar(p) => p.check().map(PayloadInvalid::ProTx),
      Self::Unknown { .. } => None,
    }
  }
}

impl SpecialPayload {
  /// Returns `true` for unrecognized transaction types.
  pub fn is_unknown(&self) -> bool {
    matches!(self, Self::Unknown { .. })
  }

  /// Returns the inputs hash a ProTx payload of a known version commits to.
  pub(crate) fn inputs_hash(&self) -> Option<InputsHash> {
    match self {
      Self::ProviderRegister(ProTxPayload::Known(payload)) => Some(payload.inputs_hash),
      Self::ProviderUpdateService(ProTxPayload::Known(payload)) => Some(payload.inputs_hash),
      Self::ProviderUpdateRegistrar(ProTxPayload::Known(payload)) => Some(payload.inputs_hash),
      Self::ProviderUpdateRevoke(ProTxPayload::Known(payload)) => Some(payload.inputs_hash),
      Self::ProviderUpdateShare(payload) => Some(payload.inputs_hash),
      Self::ProviderUpdateSharedRegistrar(payload) => Some(payload.inputs_hash),
      _ => None,
    }
  }

  /// Decodes a payload from its transaction type and raw bytes.
  ///
  /// Returns `Unknown` for unrecognized types rather than an error, ensuring
  /// forward compatibility with future transaction types.
  ///
  /// # Errors
  ///
  /// Returns `PayloadError` if a recognized type fails to decode.
  pub fn decode(tx_type: TxType, data: &mut &[u8]) -> Result<Self, PayloadError> {
    let err = |e: DecodeError| PayloadError {
      tx_type,
      message: format!("{e}"),
    };
    match tx_type {
      TxType::Spend => Err(PayloadError {
        tx_type,
        message: String::from("spend transactions have no payload"),
      }),
      TxType::ProviderRegister => ProTxPayload::decode(data).map(Self::ProviderRegister).map_err(err),
      TxType::ProviderUpdateService => ProTxPayload::decode(data).map(Self::ProviderUpdateService).map_err(err),
      TxType::ProviderUpdateRegistrar => ProTxPayload::decode(data)
        .map(Self::ProviderUpdateRegistrar)
        .map_err(err),
      TxType::ProviderUpdateRevoke => ProTxPayload::decode(data).map(Self::ProviderUpdateRevoke).map_err(err),
      TxType::CoinbaseCommitment => cbtx::CoinbaseCommitment::decode(data)
        .map(Self::CoinbaseCommitment)
        .map_err(err),
      TxType::QuorumCommitment => FinalCommitment::decode(data).map(Self::QuorumCommitment).map_err(err),
      TxType::MnhfSignal => MnHardFork::decode(data).map(Self::MnhfSignal).map_err(err),
      TxType::AssetLock => assetlock::AssetLock::decode(data).map(Self::AssetLock).map_err(err),
      TxType::AssetUnlock => assetunlock::AssetUnlock::decode(data)
        .map(Self::AssetUnlock)
        .map_err(err),
      TxType::ProviderDissolve => ProDisTx::decode(data).map(Self::ProviderDissolve).map_err(err),
      TxType::ProviderUpdateShare => ProUpShareTx::decode(data).map(Self::ProviderUpdateShare).map_err(err),
      TxType::ProviderUpdateSharedRegistrar => ProUpSharedRegTx::decode(data)
        .map(Self::ProviderUpdateSharedRegistrar)
        .map_err(err),
      unknown => {
        let bytes = data.to_vec();
        *data = &[];
        Ok(Self::Unknown {
          tx_type: unknown,
          data: bytes,
        })
      }
    }
  }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "test code")]
mod tests {
  use super::{
    MnType, PayloadInvalid, ProRegTx, ProTxInvalid, ProTxPayload, SpecialPayload, TxType, UnknownProTxVersion,
  };
  use crate::prelude::*;
  use crate::types::{NIError, NetAddrError};
  use crate::{OutPoint, Transaction, TxHash, TxIn, TxInvalid, TxOut};

  use bitcoin_primitives::script::{ScriptPubKeyBuf, ScriptSigBuf};
  use bitcoin_units::Amount;
  use dash_types::codec::{BaseCodec, DecodeError};
  use dash_types::{Checkable, Numeric};
  use rstest::rstest;

  #[rstest]
  #[case::addr(NIError::BadAddr { error: NetAddrError::BadRange { value: 0 } }, "bad-protx-netinfo-addr")]
  #[case::addr_port(NIError::BadAddr { error: NetAddrError::BadPort { port: 0 } }, "bad-protx-netinfo-port")]
  #[case::port(NIError::BadPort { port: 0 }, "bad-protx-netinfo-port")]
  #[case::addr_type(NIError::BadType { entry_type: 2 }, "bad-protx-netinfo-addr-type")]
  #[case::duplicate(NIError::Duplicate, "bad-protx-dup-netinfo-entry")]
  #[case::max_limit(NIError::MaxLimit { count: 9, max: 8 }, "bad-protx-netinfo-maxlimit")]
  #[case::malformed(NIError::Malformed, "bad-protx-netinfo-bad")]
  #[case::not_routable(NIError::NotRoutable, "bad-protx-netinfo-addr-unroutable")]
  fn net_info_errors_use_the_reference_reasons(#[case] error: NIError, #[case] reason: &str) {
    let shown = ProTxInvalid::NetInfoInvalid { error }.to_string();
    assert!(shown.starts_with(&format!("{reason}: ")), "{shown}");
  }

  #[rstest]
  #[case::regular(MnType::Regular, Some(100_000_000_000))]
  #[case::evo(MnType::Evo, Some(400_000_000_000))]
  #[case::unknown(MnType::Unknown(2), None)]
  fn collateral_amount_follows_the_type(#[case] mn_type: MnType, #[case] duffs: Option<u64>) {
    assert_eq!(mn_type.collateral_amount().map(Amount::to_sat), duffs);
  }

  #[rstest]
  #[case::zero(0, true)]
  #[case::legacy_bls(1, false)]
  #[case::ext_addr(3, false)]
  #[case::past_ext_addr(4, true)]
  #[case::max(u16::MAX, true)]
  fn unknown_versions_are_zero_and_past_ext_addr(#[case] version: u16, #[case] unknown: bool) {
    assert_eq!(UnknownProTxVersion::new(version).is_some(), unknown);
  }

  #[rstest]
  #[case::register(TxType::ProviderRegister)]
  #[case::update_service(TxType::ProviderUpdateService)]
  #[case::update_registrar(TxType::ProviderUpdateRegistrar)]
  #[case::update_revoke(TxType::ProviderUpdateRevoke)]
  fn unknown_version_payload_is_only_its_version(#[case] tx_type: TxType, #[values(0, 4)] version: u16) {
    let wire = version.to_le_bytes();
    let mut cursor = wire.as_slice();
    let payload = SpecialPayload::decode(tx_type, &mut cursor).unwrap();
    assert!(cursor.is_empty());
    assert_eq!(
      payload.check(),
      Some(PayloadInvalid::ProTx(ProTxInvalid::BadVersion { version }))
    );
  }

  #[rstest]
  fn fields_type_rejects_an_unknown_version() {
    assert!(matches!(
      ProRegTx::decode(&mut [0x04, 0x00].as_slice()),
      Err(DecodeError::InvalidValue { actual: 4, .. })
    ));
    assert!(matches!(
      ProTxPayload::<ProRegTx>::decode(&mut [0x04, 0x00].as_slice()),
      Ok(ProTxPayload::UnknownVersion(version)) if version.version() == 4
    ));
  }

  fn special(tx_type: TxType, extra_payload: Vec<u8>) -> Transaction {
    Transaction {
      version: 3,
      tx_type,
      inputs: vec![TxIn {
        prevout: OutPoint {
          hash: TxHash::from_lendian([0x11; 32]),
          index: 0,
        },
        script_sig: ScriptSigBuf::new(),
        sequence: u32::MAX,
      }],
      outputs: vec![TxOut {
        value: Amount::ZERO,
        script_pubkey: ScriptPubKeyBuf::new(),
      }],
      lock_time: 0,
      extra_payload,
    }
  }

  #[rstest]
  fn transaction_check_reports_the_version_and_rejects_trailing_bytes() {
    let tx = special(TxType::ProviderUpdateRevoke, vec![0x00, 0x00]);
    assert_eq!(
      tx.check(),
      Some(TxInvalid::PayloadCheck(PayloadInvalid::ProTx(
        ProTxInvalid::BadVersion { version: 0 }
      )))
    );

    let tx = special(TxType::ProviderUpdateRevoke, vec![0x00, 0x00, 0x00]);
    assert!(matches!(tx.check(), Some(TxInvalid::PayloadDecode(_))));
  }

  #[cfg(feature = "serde")]
  fn corpus_transactions<T: ::serde::de::DeserializeOwned>(section: &str) -> Vec<Transaction> {
    let corpus = dash_dev::Corpus::open(env!("CARGO_MANIFEST_DIR"), section);
    let mut txs = Vec::new();
    corpus.entries::<T>(section, |raw, _, _| {
      txs.push(Transaction::decode(&mut &raw[..]).unwrap())
    });
    txs
  }

  #[cfg(feature = "serde")]
  #[rstest]
  #[case::dissolve(corpus_transactions::<crate::ProDisTx>("prodistx"), TxType::ProviderDissolve)]
  #[case::update_share(corpus_transactions::<crate::ProUpShareTx>("proupsharetx"), TxType::ProviderUpdateShare)]
  #[case::update_shared_registrar(
    corpus_transactions::<crate::ProUpSharedRegTx>("proupsharedregtx"),
    TxType::ProviderUpdateSharedRegistrar
  )]
  fn types_10_to_12_decode_and_pass_checks(#[case] txs: Vec<Transaction>, #[case] tx_type: TxType) {
    for tx in txs {
      assert_eq!(tx.tx_type, tx_type);
      let payload = tx.decode_payload().unwrap().unwrap();
      let matches_type = match tx_type {
        TxType::ProviderDissolve => matches!(payload, SpecialPayload::ProviderDissolve(_)),
        TxType::ProviderUpdateShare => matches!(payload, SpecialPayload::ProviderUpdateShare(_)),
        _ => matches!(payload, SpecialPayload::ProviderUpdateSharedRegistrar(_)),
      };
      assert!(matches_type, "{tx_type}");
      assert_eq!(tx.check(), None, "{tx_type}");
    }
  }

  #[rstest]
  #[case::dissolve(10, "provider_dissolve")]
  #[case::update_share(11, "provider_update_share")]
  #[case::update_shared_registrar(12, "provider_update_shared_registrar")]
  fn types_10_to_12_are_known(#[case] code: u16, #[case] name: &str) {
    let tx_type = TxType::from_base(code);
    assert!(!matches!(tx_type, TxType::Unknown(_)));
    assert_eq!(tx_type.to_string(), name);
  }

  /// A payload of types 10 to 12 runs its own check rather than failing as
  /// an unknown type.
  #[rstest]
  fn type_10_payload_reports_its_own_check() {
    let mut payload = 0u16.to_le_bytes().to_vec();
    payload.extend([0; 34]);
    payload.push(0);
    let tx = special(TxType::ProviderDissolve, payload);
    assert_eq!(
      tx.check(),
      Some(TxInvalid::PayloadCheck(PayloadInvalid::ProTx(
        ProTxInvalid::BadDissolveVersion { version: 0 }
      )))
    );
  }
}
