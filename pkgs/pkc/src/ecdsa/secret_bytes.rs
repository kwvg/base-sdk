//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! secp256k1 secret key byte bag.

use crate::prelude::*;

use cfg_if::cfg_if;
use dash_types::{impl_bytes, TypeId};
use hex_conservative::{DisplayHex, FromHex};
use zeroize::{Zeroize, ZeroizeOnDrop};

use core::fmt::{self, Debug, Display, Formatter};

/// Raw ECDSA secret key bytes.
#[derive(Clone, Default, Eq, PartialEq, TypeId, Zeroize, ZeroizeOnDrop)]
pub struct EcdsaSkBytes(pub [u8; 32]);

impl_bytes!(32, EcdsaSkBytes);

impl EcdsaSkBytes {
  /// Returns the inner byte array.
  pub fn to_bytes(self) -> [u8; 32] {
    self.0
  }

  /// Borrows the inner byte array.
  pub const fn as_bytes(&self) -> &[u8; 32] {
    &self.0
  }

  /// Returns `true` when every byte is zero.
  pub fn is_null(&self) -> bool {
    self.0.iter().all(|&b| b == 0)
  }
}

impl AsRef<[u8]> for EcdsaSkBytes {
  fn as_ref(&self) -> &[u8] {
    &self.0
  }
}

impl AsRef<[u8; 32]> for EcdsaSkBytes {
  fn as_ref(&self) -> &[u8; 32] {
    &self.0
  }
}

impl Debug for EcdsaSkBytes {
  fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
    write!(f, "EcdsaSkBytes(..)")
  }
}

impl Display for EcdsaSkBytes {
  fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
    Debug::fmt(self, f)
  }
}

impl From<EcdsaSkBytes> for [u8; 32] {
  fn from(val: EcdsaSkBytes) -> Self {
    val.0
  }
}

cfg_if! {
  if #[cfg(feature = "serde")] {
    use serde::{Serialize, Serializer, Deserialize, Deserializer, de::Error as DeError};

    impl Serialize for EcdsaSkBytes {
      fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0.to_lower_hex_string())
      }
    }

    impl<'de> Deserialize<'de> for EcdsaSkBytes {
      fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = <String as Deserialize>::deserialize(deserializer)?;
        <[u8; 32] as FromHex>::from_hex(&s)
          .map(Self)
          .map_err(DeError::custom)
      }
    }
  }
}
