//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Shared trait definitions.

/// Consensus types that have internal consistency checks.
pub trait Checkable {
  /// The error type returned on failure.
  type Error;

  /// Checks structural invariants, returning the first violation.
  #[must_use]
  fn check(&self) -> Option<Self::Error>;
}

/// Canonical hashed representation.
pub trait Hashable {
  /// The hash output type.
  type Hash;

  /// Computes the canonical hash of this value.
  fn hash(&self) -> Self::Hash;
}
