//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Reusable serde helpers for `#[serde(with = "...")]`.

use crate::hash::{hex_val, HEX_LOWER};
use crate::prelude::*;
use crate::ParseHexError;

/// Hex-encode bytes in big-endian (display) order.
fn encode_be(bytes: &[u8]) -> String {
  let mut s = String::with_capacity(bytes.len() * 2);
  for &b in bytes.iter().rev() {
    s.push(HEX_LOWER[(b >> 4) as usize] as char);
    s.push(HEX_LOWER[(b & 0xf) as usize] as char);
  }
  s
}

/// Decode a big-endian hex string into a little-endian byte array.
fn decode_be<const N: usize>(s: &str) -> Result<[u8; N], ParseHexError> {
  let b = s.as_bytes();
  if b.len() % 2 != 0 {
    return Err(ParseHexError::OddLength);
  }
  let byte_len = b.len() / 2;
  if byte_len != N {
    return Err(ParseHexError::InvalidLength {
      expected: N * 2,
      got: b.len(),
    });
  }
  let mut out = [0u8; N];
  let mut i = 0;
  while i < byte_len {
    let hi = hex_val(b[i * 2])?;
    let lo = hex_val(b[i * 2 + 1])?;
    out[byte_len - 1 - i] = (hi << 4) | lo;
    i += 1;
  }
  Ok(out)
}

/// hex_blob stores bytes in little-endian internally but display in
/// big-endian (MSB first).
pub mod hex_blob {
  use super::*;

  macro_rules! define_fixed {
    ($mod_name:ident, $n:literal) => {
      #[doc = concat!("Big-endian hex for `[u8; ", stringify!($n), "]`.")]
      pub mod $mod_name {
        use super::*;

        /// Serializes as a big-endian hex string.
        pub fn serialize<S: serde::Serializer>(data: &[u8; $n], serializer: S) -> Result<S::Ok, S::Error> {
          serializer.serialize_str(&encode_be(data))
        }

        /// Deserializes a big-endian hex string into a little-endian array.
        pub fn deserialize<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<[u8; $n], D::Error> {
          let s = <String as serde::Deserialize>::deserialize(deserializer)?;
          decode_be::<$n>(&s).map_err(serde::de::Error::custom)
        }
      }
    };
  }

  define_fixed!(w20, 20);
  define_fixed!(w32, 32);
  define_fixed!(w64, 64);
}
