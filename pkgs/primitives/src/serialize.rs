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

/// Serializes [`Amount`](bitcoin_units::Amount) as a JSON number of whole
/// coins, written as an integer when the amount has no fraction.
pub mod coins {
  use crate::prelude::*;

  use bitcoin_units::Amount;

  const COIN: u64 = 100_000_000;

  /// Serializes as a number of coins.
  pub fn serialize<S: serde::Serializer>(val: &Amount, serializer: S) -> Result<S::Ok, S::Error> {
    let sat = val.to_sat();
    if sat % COIN == 0 {
      serializer.serialize_u64(sat / COIN)
    } else {
      serializer.serialize_f64(sat as f64 / COIN as f64)
    }
  }

  /// Deserializes from a number of coins, integer or float. A float rounds to
  /// the nearest satoshi.
  pub fn deserialize<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<Amount, D::Error> {
    struct Visitor;

    impl serde::de::Visitor<'_> for Visitor {
      type Value = Amount;

      fn expecting(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("a non-negative number of coins")
      }

      fn visit_u64<E: serde::de::Error>(self, v: u64) -> Result<Amount, E> {
        let sat = v.checked_mul(COIN).ok_or_else(|| E::custom("amount overflow"))?;
        Amount::from_sat(sat).map_err(E::custom)
      }

      fn visit_i64<E: serde::de::Error>(self, v: i64) -> Result<Amount, E> {
        let v: u64 = v.try_into().map_err(|_| E::custom("negative amount"))?;
        self.visit_u64(v)
      }

      fn visit_f64<E: serde::de::Error>(self, v: f64) -> Result<Amount, E> {
        if !v.is_finite() || v < 0.0 {
          return Err(E::custom("invalid amount"));
        }
        let sat = round(v * COIN as f64);
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
  use crate::types::{BlsScheme, BlsSig};

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

  /// Reads a hex signature whose field the format fixes as basic.
  ///
  /// # Errors
  ///
  /// Returns an error when the input is not 96 bytes of hex.
  pub fn sig_basic<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<BlsSig, D::Error> {
    Ok(BlsSig::from_bytes(bytes(deserializer)?, BlsScheme::Basic))
  }

  /// Reads an optional hex signature whose field the format fixes as basic.
  ///
  /// # Errors
  ///
  /// Returns an error when the input is neither null nor 96 bytes of hex.
  pub fn sig_basic_opt<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<Option<BlsSig>, D::Error> {
    match <Option<String> as serde::Deserialize>::deserialize(deserializer)? {
      Some(hex) => decode_to_array(&hex)
        .map(|sig| Some(BlsSig::from_bytes(sig, BlsScheme::Basic)))
        .map_err(serde::de::Error::custom),
      None => Ok(None),
    }
  }

  fn bytes<'de, const N: usize, D: serde::Deserializer<'de>>(deserializer: D) -> Result<[u8; N], D::Error> {
    let hex = <String as serde::Deserialize>::deserialize(deserializer)?;
    decode_to_array(&hex).map_err(serde::de::Error::custom)
  }
}
