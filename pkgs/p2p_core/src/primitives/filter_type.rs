//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Compact block filter type identifier.

dash_types::make_num! {
  /// BIP157 filter type, encoded as a single byte on the wire.
  FilterType, u8, 1
}

impl FilterType {
  /// Basic filter (the only type defined by BIP158).
  pub const BASIC: Self = Self(0);
}
