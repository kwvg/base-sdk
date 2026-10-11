//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Protocol version.

use dash_primitives::hash_impl;
use dash_types::make_num;

make_num! {
  /// Protocol version exchanged during the handshake.
  ProtocolVersion, u32, 4
}

hash_impl!(ProtocolVersion);

impl ProtocolVersion {
  /// Current protocol version.
  pub const CURRENT: Self = Self(70242);
  /// Minimum acceptable peer version.
  pub const MIN_PEER: Self = Self(70221);
  /// Minimum version for BIP324 v2 transport.
  pub const BIP324_BASELINE: Self = Self(70235);
  /// Minimum masternode version accepted in DKGs.
  pub const MIN_MASTERNODE: Self = Self(70242);
  /// BIP155 addrv2 version boundary.
  pub const ADDRV2: Self = Self(70223);
  /// BLS signature scheme version boundary.
  pub const BLS_SCHEME: Self = Self(70225);
  /// Masternode type field version boundary.
  pub const DMN_TYPE: Self = Self(70227);
  /// Versioned simplified MN list entry boundary.
  pub const SMNLE_VERSIONED: Self = Self(70228);
  /// MN list diff version-first ordering boundary.
  pub const MNLISTDIFF_VERSION_ORDER: Self = Self(70229);
  /// Chainlock signatures in MN list diff boundary.
  pub const MNLISTDIFF_CHAINLOCKS: Self = Self(70230);
  /// Legacy InstantSend lock removal boundary.
  pub const NO_LEGACY_ISLOCK: Self = Self(70231);
  /// CoinJoin queue inventory type boundary.
  pub const DSQ_INV: Self = Self(70234);
  /// Compressed header batch limit increase boundary.
  pub const INCREASE_MAX_HEADERS2: Self = Self(70235);
  /// Quorum rotation info behaviour change boundary.
  pub const EFFICIENT_QRINFO: Self = Self(70236);
  /// InstantSend lock cycle hash change boundary.
  pub const ISDLOCK_CYCLEHASH_UPDATE: Self = Self(70237);
  /// Platform ban message boundary.
  pub const PLATFORM_BAN: Self = Self(70238);
  /// Stale quorum commitment relay ban boundary.
  pub const QFCOMMIT_STALE_REPROP_BAN: Self = Self(70239);
  /// Platform ban BIP324 short ID boundary.
  pub const PLATFORMBAN_V2_SHORT_ID: Self = Self(70240);
  /// CoinJoin rebalance session and `dsa` flags boundary.
  pub const COINJOIN_REBALANCE: Self = Self(70241);
  /// Asset unlock inventory type boundary.
  pub const ASSET_UNLOCK_INV: Self = Self(70242);
}
