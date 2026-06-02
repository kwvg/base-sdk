//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Shared validation context and helpers.
//!
//! Type-specific validation lives in each type's own module. This module
//! provides the deployment context and helpers shared across multiple modules.

use crate::prelude::*;
use crate::support::{NetInfoEntry, NetInfoPurpose};
use crate::tx_types::MnType;

use core::fmt;

/// Maximum serialized transaction size (single tx, always 1 MB).
pub(crate) const MAX_LEGACY_BLOCK_SIZE: usize = 1_000_000;

/// Post-DIP0001 maximum block size (2 MB).
pub(crate) const MAX_DIP0001_BLOCK_SIZE: usize = 2_000_000;

/// Maximum extra payload size in bytes.
pub(crate) const MAX_TX_EXTRA_PAYLOAD: usize = 10_000;

/// Number of version bits available for signalling.
pub(crate) const VERSIONBITS_NUM_BITS: u8 = 29;

/// Maximum coinbase script size in bytes.
pub(crate) const MAX_COINBASE_SCRIPT_SIZE: usize = 100;

/// Maximum operator reward in basis points.
pub(crate) const MAX_OPERATOR_REWARD: u16 = 10_000;

/// Maximum allowed name length for governance proposals.
pub(crate) const MAX_PROPOSAL_NAME_LEN: usize = 40;

/// Minimum URL length for governance proposals.
pub(crate) const MIN_URL_LEN: usize = 4;

/// Allowed characters in governance proposal names.
pub(crate) const PROPOSAL_NAME_CHARS: &[u8] = b"-_abcdefghijklmnopqrstuvwxyz0123456789";

/// ProTx version: legacy BLS operator keys (v1).
pub(crate) const PROTX_VERSION_LEGACY_BLS: u16 = 1;

/// ProTx version: basic (IETF) BLS operator keys (v2).
pub(crate) const PROTX_VERSION_BASIC_BLS: u16 = 2;

/// ProTx version: extended network addresses (v3).
pub(crate) const PROTX_VERSION_EXT_ADDR: u16 = 3;

/// Deployment activation state for fork-gated validation.
///
/// Each field is tri-state: `Some(true)` means the fork is active,
/// `Some(false)` means it is not yet active, and `None` means the caller does
/// not know and the corresponding checks should be skipped.
#[derive(Clone, Debug, Default, Eq, Hash, PartialEq)]
pub struct DeploymentContext {
  /// DIP0001 (2 MB blocks, relaxed sigops).
  pub dip0001_active: Option<bool>,
  /// DIP0003 (special transactions).
  pub dip0003_active: Option<bool>,
  /// DIP0008 (merkle root quorums in CbTx).
  pub dip0008_active: Option<bool>,
  /// V19 (BasicBLS operator keys).
  pub basic_bls_active: Option<bool>,
  /// V20 (ChainLock signature + credit pool in CbTx).
  pub v20_active: Option<bool>,
  /// V24 (extended network addresses).
  pub ext_addr_active: Option<bool>,
}

/// Provider transaction validation failure.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
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
  /// `bad-protx-netinfo-version`
  NetInfoVersionMismatch,
  /// `bad-protx-netinfo-empty`
  NetInfoEmpty,
  /// `bad-protx-netinfo-bad`
  NetInfoInvalid,
  /// `bad-protx-payee-reuse`
  PayoutKeyReuse,
  /// `bad-protx-operator-reward`
  OperatorRewardTooHigh { reward: u16 },
  /// `bad-protx-reason`
  BadReason { reason: crate::support::RevocationReason },
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
      Self::NetInfoVersionMismatch => write!(f, "bad-protx-netinfo-version"),
      Self::NetInfoEmpty => write!(f, "bad-protx-netinfo-empty"),
      Self::NetInfoInvalid => write!(f, "bad-protx-netinfo-bad"),
      Self::PayoutKeyReuse => write!(f, "bad-protx-payee-reuse"),
      Self::OperatorRewardTooHigh { reward } => write!(f, "bad-protx-operator-reward: {reward}"),
      Self::BadReason { reason } => write!(f, "bad-protx-reason: {reason}"),
    }
  }
}

/// Returns the maximum ProTx version given deployment state, or `None` when the
/// check should be skipped.
pub(crate) fn max_protx_version(ctx: &DeploymentContext) -> Option<u16> {
  if ctx.ext_addr_active == Some(true) {
    return Some(PROTX_VERSION_EXT_ADDR);
  }
  if ctx.basic_bls_active == Some(true) {
    return Some(PROTX_VERSION_BASIC_BLS);
  }
  if ctx.basic_bls_active == Some(false) && ctx.ext_addr_active != Some(true) {
    return Some(PROTX_VERSION_LEGACY_BLS);
  }
  None
}

/// Returns the maximum version for ProUpRegTx / ProUpRevTx (no extended address
/// version for these types).
pub(crate) fn max_protx_version_no_ext(ctx: &DeploymentContext) -> Option<u16> {
  if ctx.basic_bls_active == Some(true) {
    return Some(PROTX_VERSION_BASIC_BLS);
  }
  if ctx.basic_bls_active == Some(false) {
    return Some(PROTX_VERSION_LEGACY_BLS);
  }
  None
}

/// Checks that version > 0 and optionally <= max.
pub(crate) fn check_protx_version(version: u16, max: Option<u16>) -> Result<(), ProTxInvalid> {
  if version == 0 {
    return Err(ProTxInvalid::BadVersion { version });
  }
  if let Some(max) = max {
    if version > max {
      return Err(ProTxInvalid::BadVersion { version });
    }
  }
  Ok(())
}

/// Checks that a BLS operator public key is not all zeros.
pub(crate) fn check_operator_key_not_null(key: &dash_types::BlsPublicKeyBytes) -> Result<(), ProTxInvalid> {
  if key.is_null() {
    return Err(ProTxInvalid::NullKey);
  }
  Ok(())
}

/// Checks that an extended net info payload is trivially valid.
pub(crate) fn check_net_info_trivially_valid(
  entries: &[(NetInfoPurpose, Vec<NetInfoEntry>)],
  mn_type: MnType,
  can_store_platform: bool,
) -> Result<(), ProTxInvalid> {
  let has_core = entries
    .iter()
    .any(|(p, e)| *p == NetInfoPurpose::CoreP2p && !e.is_empty());
  if !has_core {
    return Err(ProTxInvalid::NetInfoEmpty);
  }

  let has_platform_p2p = entries
    .iter()
    .any(|(p, e)| *p == NetInfoPurpose::PlatformP2p && !e.is_empty());
  let has_platform_https = entries
    .iter()
    .any(|(p, e)| *p == NetInfoPurpose::PlatformHttps && !e.is_empty());

  if mn_type == MnType::Regular && (has_platform_p2p || has_platform_https) {
    return Err(ProTxInvalid::NetInfoInvalid);
  }

  if can_store_platform && mn_type == MnType::Evo && (!has_platform_p2p || !has_platform_https) {
    return Err(ProTxInvalid::NetInfoEmpty);
  }

  for (_purpose, group) in entries {
    for entry in group {
      if matches!(entry, NetInfoEntry::Invalid) {
        return Err(ProTxInvalid::NetInfoInvalid);
      }
    }
  }

  Ok(())
}
