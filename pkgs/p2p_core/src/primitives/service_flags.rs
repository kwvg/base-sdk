//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Dash service flag bitfield.

use dash_types::codec::NumCodec;

use core::fmt;
use core::ops;

/// Bitfield advertised in `version` messages describing node capabilities.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct ServiceFlags(pub u64);

impl ServiceFlags {
  /// No services.
  pub const NONE: Self = Self(0);
  /// Full blockchain data.
  pub const NODE_NETWORK: Self = Self(1 << 0);
  /// BIP37 bloom filters.
  pub const NODE_BLOOM: Self = Self(1 << 2);
  /// BIP157 compact block filters.
  pub const NODE_COMPACT_FILTERS: Self = Self(1 << 6);
  /// Last 288 blocks only.
  pub const NODE_NETWORK_LIMITED: Self = Self(1 << 10);
  /// Dash compressed headers (headers2).
  pub const NODE_HEADERS_COMPRESSED: Self = Self(1 << 11);
  /// BIP324 v2 transport.
  pub const NODE_P2P_V2: Self = Self(1 << 12);

  /// Returns `true` if all bits in `flag` are set.
  pub const fn has(self, flag: Self) -> bool {
    self.0 & flag.0 == flag.0
  }

  /// Returns the raw `u64` value.
  pub const fn to_u64(self) -> u64 {
    self.0
  }
}

impl NumCodec<u64> for ServiceFlags {
  fn from_base(v: u64) -> Self {
    Self(v)
  }

  fn to_base(&self) -> u64 {
    self.0
  }
}

impl ops::BitOr for ServiceFlags {
  type Output = Self;
  fn bitor(self, rhs: Self) -> Self {
    Self(self.0 | rhs.0)
  }
}

impl ops::BitAnd for ServiceFlags {
  type Output = Self;
  fn bitand(self, rhs: Self) -> Self {
    Self(self.0 & rhs.0)
  }
}

impl ops::BitOrAssign for ServiceFlags {
  fn bitor_assign(&mut self, rhs: Self) {
    self.0 |= rhs.0;
  }
}

impl fmt::Debug for ServiceFlags {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "ServiceFlags(0x{:016x})", self.0)
  }
}

impl fmt::Display for ServiceFlags {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "0x{:x}", self.0)
  }
}

dash_types::impl_num!(ServiceFlags, u64);
