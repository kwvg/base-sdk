//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Transaction type and masternode type enums.

use core::fmt;

/// Dash transaction type, encoded in the upper 16 bits of the version field.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum TxType {
  /// Spend transaction (includes legacy coinbase).
  Spend,
  /// Masternode registration (type 1).
  ProviderRegister,
  /// Masternode service address update (type 2).
  ProviderUpdateService,
  /// Masternode registrar key update (type 3).
  ProviderUpdateRegistrar,
  /// Masternode revocation (type 4).
  ProviderUpdateRevoke,
  /// Coinbase commitment special transaction (type 5).
  CoinbaseCommitment,
  /// LLMQ final commitment (type 6).
  QuorumCommitment,
  /// Masternode hard fork signal (type 7).
  MnhfSignal,
  /// Asset lock: L1 to platform (type 8).
  AssetLock,
  /// Asset unlock: platform to L1 (type 9).
  AssetUnlock,
  /// Unknown or future transaction type.
  Unknown(u16),
}

impl TxType {
  /// Converts a raw `u16` to a `TxType`.
  pub const fn from_u16(value: u16) -> Self {
    match value {
      0 => Self::Spend,
      1 => Self::ProviderRegister,
      2 => Self::ProviderUpdateService,
      3 => Self::ProviderUpdateRegistrar,
      4 => Self::ProviderUpdateRevoke,
      5 => Self::CoinbaseCommitment,
      6 => Self::QuorumCommitment,
      7 => Self::MnhfSignal,
      8 => Self::AssetLock,
      9 => Self::AssetUnlock,
      other => Self::Unknown(other),
    }
  }

  /// Converts a `TxType` to its raw `u16` value.
  pub const fn to_u16(self) -> u16 {
    match self {
      Self::Spend => 0,
      Self::ProviderRegister => 1,
      Self::ProviderUpdateService => 2,
      Self::ProviderUpdateRegistrar => 3,
      Self::ProviderUpdateRevoke => 4,
      Self::CoinbaseCommitment => 5,
      Self::QuorumCommitment => 6,
      Self::MnhfSignal => 7,
      Self::AssetLock => 8,
      Self::AssetUnlock => 9,
      Self::Unknown(v) => v,
    }
  }
}

impl fmt::Display for TxType {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    match self {
      Self::Spend => write!(f, "spend"),
      Self::ProviderRegister => write!(f, "provider_register"),
      Self::ProviderUpdateService => write!(f, "provider_update_service"),
      Self::ProviderUpdateRegistrar => write!(f, "provider_update_registrar"),
      Self::ProviderUpdateRevoke => write!(f, "provider_update_revoke"),
      Self::CoinbaseCommitment => write!(f, "coinbase_commitment"),
      Self::QuorumCommitment => write!(f, "quorum_commitment"),
      Self::MnhfSignal => write!(f, "mnhf_signal"),
      Self::AssetLock => write!(f, "asset_lock"),
      Self::AssetUnlock => write!(f, "asset_unlock"),
      Self::Unknown(v) => write!(f, "unknown({v})"),
    }
  }
}

/// Masternode type, used in provider registration and update transactions.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum MnType {
  /// Regular masternode.
  Regular,
  /// Evolution (Evo) masternode with platform capabilities.
  Evo,
  /// Unknown or future masternode type.
  Unknown(u16),
}

impl MnType {
  /// Converts a raw `u16` to a `MnType`.
  pub const fn from_u16(value: u16) -> Self {
    match value {
      0 => Self::Regular,
      1 => Self::Evo,
      other => Self::Unknown(other),
    }
  }

  /// Converts a `MnType` to its raw `u16` value.
  pub const fn to_u16(self) -> u16 {
    match self {
      Self::Regular => 0,
      Self::Evo => 1,
      Self::Unknown(v) => v,
    }
  }
}

impl fmt::Display for MnType {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    match self {
      Self::Regular => write!(f, "regular"),
      Self::Evo => write!(f, "evo"),
      Self::Unknown(v) => write!(f, "unknown({v})"),
    }
  }
}
