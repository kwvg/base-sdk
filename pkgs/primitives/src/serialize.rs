//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Reusable serde helpers for `#[serde(with = "...")]`.

/// Serializes [`Amount`](bitcoin_units::Amount) as a `u64` (satoshis).
pub mod amount {
  use bitcoin_units::Amount;

  /// Serializes as raw satoshis.
  pub fn serialize<S: serde::Serializer>(val: &Amount, serializer: S) -> Result<S::Ok, S::Error> {
    serializer.serialize_u64(val.to_sat())
  }

  /// Deserializes from raw satoshis.
  pub fn deserialize<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<Amount, D::Error> {
    let sat = <u64 as serde::Deserialize>::deserialize(deserializer)?;
    Amount::from_sat(sat).map_err(serde::de::Error::custom)
  }
}
