//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Deployment states that gate consensus checks.

use dash_types::type_id::Unencodable;

/// Whether a deployment is active at the block being validated.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Unencodable)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub enum Activation {
  /// The deployment's rules apply.
  Active,
  /// The deployment's rules do not apply yet.
  Inactive,
}

/// Activation of each deployment a gated check reads.
///
/// The chain decides, so callers pass the states at the block they validate.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Unencodable)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct Deployments {
  /// The v19 hard fork.
  pub v19: Activation,
  /// The v20 hard fork.
  pub v20: Activation,
  /// The v24 hard fork.
  pub v24: Activation,
  /// EvoNode shared collateral and multiple owner payouts.
  pub evo_shares: Activation,
}
