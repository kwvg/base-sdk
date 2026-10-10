//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Building blocks shared by the ProTx payloads.

use crate::{codec_type, hash_impl};

use bitcoin_primitives::script::ScriptPubKeyBuf;
use dash_script::PubKeyHash;
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

/// One entry of a masternode's owner payout list.
#[derive(Clone, Debug, Eq, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub struct MasternodePayoutShare {
  /// Script the share of the owner reward pays to.
  pub script_payout: ScriptPubKeyBuf,
  /// Share of the owner reward in basis points.
  pub reward: u16,
}

codec_type!(MasternodePayoutShare { script_payout, reward });

/// One participant's contribution to a shared masternode collateral.
#[derive(Clone, Debug, Eq, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub struct CollateralShare {
  /// Contributed amount in duffs.
  ///
  /// The wire carries any signed amount, so an out-of-range amount decodes
  /// and fails the checks.
  pub amount: i64,
  /// Script the contribution is refunded to.
  pub script_refund: ScriptPubKeyBuf,
  /// Script the share of the owner reward pays to; an empty script pays
  /// `script_refund`.
  pub script_reward: ScriptPubKeyBuf,
  /// Key id of the participant's owner key.
  pub key_id_owner: PubKeyHash,
}

codec_type!(CollateralShare {
  amount,
  script_refund,
  script_reward,
  key_id_owner
});

#[cfg(test)]
mod tests {
  use super::{CollateralShare, CompactSignature, MasternodePayoutShare};
  use crate::prelude::*;

  use bitcoin_primitives::script::ScriptPubKeyBuf;
  use dash_script::PubKeyHash;
  use dash_types::codec::{BaseCodec, DecodeError};
  use dash_types::Numeric;
  use hex_conservative::hex;
  use rstest::rstest;

  fn encoded(item: &impl BaseCodec) -> Vec<u8> {
    let mut buf = Vec::new();
    item.encode(&mut buf);
    buf
  }

  #[rstest]
  fn payout_share_is_a_script_then_a_u16_reward() {
    let share = MasternodePayoutShare {
      script_payout: ScriptPubKeyBuf::from_bytes(hex!("76a914").to_vec()),
      reward: 0x2710,
    };
    let wire = encoded(&share);
    assert_eq!(wire, hex!("0376a9141027"));
    assert_eq!(MasternodePayoutShare::decode(&mut wire.as_slice()), Ok(share));
  }

  #[rstest]
  fn collateral_share_is_an_i64_amount_two_scripts_and_an_owner() {
    let share = CollateralShare {
      amount: -1,
      script_refund: ScriptPubKeyBuf::from_bytes(vec![0x51]),
      script_reward: ScriptPubKeyBuf::new(),
      key_id_owner: PubKeyHash::from_lendian([0xab; 20]),
    };
    let wire = encoded(&share);
    let expected = [&[0xff; 8][..], &[0x01, 0x51, 0x00], &[0xab; 20]].concat();
    assert_eq!(wire, expected);
    assert_eq!(CollateralShare::decode(&mut wire.as_slice()), Ok(share));
  }

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
