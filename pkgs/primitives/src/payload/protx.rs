//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Building blocks shared by the ProTx payloads.

use crate::hash_impl;

use dash_types::type_id::TypeId;
use dash_types::{derive_bytes, impl_bytes};

/// Length of a compact recoverable ECDSA signature.
const COMPACT_SIGNATURE_LEN: usize = 65;

/// Compact recoverable ECDSA signature, carried as 65 raw bytes without a
/// length prefix.
///
/// The bytes stay as decoded, so the header and the low-S form are checked
/// only when the signature is verified.
#[derive(TypeId)]
pub struct CompactSignature([u8; COMPACT_SIGNATURE_LEN]);

impl_bytes!(CompactSignature, COMPACT_SIGNATURE_LEN);

hash_impl!(CompactSignature);

impl CompactSignature {
  /// Wraps the raw signature bytes.
  pub const fn from_bytes(bytes: [u8; COMPACT_SIGNATURE_LEN]) -> Self {
    Self(bytes)
  }

  /// The raw signature bytes.
  pub const fn as_bytes(&self) -> &[u8; COMPACT_SIGNATURE_LEN] {
    &self.0
  }
}

derive_bytes!(CompactSignature, COMPACT_SIGNATURE_LEN);

#[cfg(test)]
mod tests {
  use super::CompactSignature;
  use crate::prelude::*;

  use dash_types::codec::{BaseCodec, DecodeError};
  use rstest::rstest;

  #[rstest]
  fn compact_signature_is_65_raw_bytes() {
    let bytes: [u8; 65] = core::array::from_fn(|i| i as u8);
    let sig = CompactSignature::from_bytes(bytes);
    let mut buf = Vec::new();
    sig.encode(&mut buf);
    assert_eq!(buf, bytes);
    assert_eq!(CompactSignature::decode(&mut buf.as_slice()), Ok(sig));
  }

  #[rstest]
  fn compact_signature_needs_65_bytes() {
    assert!(matches!(
      CompactSignature::decode(&mut [0u8; 64].as_slice()),
      Err(DecodeError::Eof { .. })
    ));
  }

  #[cfg(feature = "serde")]
  #[rstest]
  fn compact_signature_serializes_as_hex() {
    use dash_dev::{from_json, to_json};

    let sig = CompactSignature::from_bytes([0x1f; 65]);
    assert_eq!(to_json(&sig), format!("\"{}\"", "1f".repeat(65)));
    assert_eq!(from_json::<CompactSignature>(&to_json(&sig)), sig);
  }
}
