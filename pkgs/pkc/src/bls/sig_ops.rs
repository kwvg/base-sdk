//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Common BLS signature definitions.

/// BLS signature variant (determines the DST).
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub enum BlsSigId {
  /// Basic scheme (NUL augmentation).
  Basic,
  /// Proof of Possession scheme.
  ProofOfPossession,
}
