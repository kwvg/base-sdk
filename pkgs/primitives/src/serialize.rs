//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Reusable serde helpers for `#[serde(with = "...")]`.

/// Serializes [`Amount`](bitcoin_units::Amount) as satoshis.
///
/// Integers are treated as satoshis; floats are treated as whole
/// coins and converted to satoshis.
pub mod amount {
  use crate::prelude::*;

  use bitcoin_units::Amount;

  /// Serializes as raw satoshis.
  pub fn serialize<S: serde::Serializer>(val: &Amount, serializer: S) -> Result<S::Ok, S::Error> {
    serializer.serialize_u64(val.to_sat())
  }

  /// Deserializes from satoshis (`u64`) or coins (`f64`).
  pub fn deserialize<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<Amount, D::Error> {
    struct Visitor;

    impl serde::de::Visitor<'_> for Visitor {
      type Value = Amount;

      fn expecting(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("an integer (satoshis) or float (coins)")
      }

      fn visit_u64<E: serde::de::Error>(self, v: u64) -> Result<Amount, E> {
        Amount::from_sat(v).map_err(E::custom)
      }

      fn visit_i64<E: serde::de::Error>(self, v: i64) -> Result<Amount, E> {
        let v: u64 = v.try_into().map_err(|_| E::custom("negative amount"))?;
        Amount::from_sat(v).map_err(E::custom)
      }

      fn visit_f64<E: serde::de::Error>(self, v: f64) -> Result<Amount, E> {
        if !v.is_finite() || v < 0.0 {
          return Err(E::custom("invalid amount"));
        }
        let sat = round(v * Amount::ONE_BTC.to_sat() as f64);
        if sat > u64::MAX as f64 {
          return Err(E::custom("amount overflow"));
        }
        Amount::from_sat(sat as u64).map_err(E::custom)
      }
    }

    deserializer.deserialize_any(Visitor)
  }
}

/// Deserializers for the bytes of a BLS field, which serializes as bare hex.
///
/// The JSON image carries no scheme, so the container tags the bytes from its
/// own version.
pub mod bls {
  use crate::prelude::*;

  use dash_pkc::bls::{BLS_PK_LEN, BLS_SIG_LEN};
  use hex_conservative::decode_to_array;

  /// Reads the hex bytes of a public key.
  ///
  /// # Errors
  ///
  /// Returns an error when the input is not 48 bytes of hex.
  pub fn pk_bytes<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<[u8; BLS_PK_LEN], D::Error> {
    bytes(deserializer)
  }

  /// Reads the hex bytes of a signature.
  ///
  /// # Errors
  ///
  /// Returns an error when the input is not 96 bytes of hex.
  pub fn sig_bytes<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<[u8; BLS_SIG_LEN], D::Error> {
    bytes(deserializer)
  }

  fn bytes<'de, const N: usize, D: serde::Deserializer<'de>>(deserializer: D) -> Result<[u8; N], D::Error> {
    let hex = <String as serde::Deserialize>::deserialize(deserializer)?;
    decode_to_array(&hex).map_err(serde::de::Error::custom)
  }
}
