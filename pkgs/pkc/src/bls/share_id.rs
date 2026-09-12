//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Threshold participant identifier.

use dash_types::make_bytes;

/// Threshold participant identifier length.
pub const BLS_ID_LEN: usize = 32;

make_bytes! {
  /// Threshold participant identifier.
  BlsShareId, BLS_ID_LEN, rev, nocodec
}
