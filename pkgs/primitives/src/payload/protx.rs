//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Building blocks shared by the ProTx payloads.

use super::ProTxInvalid;
use crate::prelude::*;
use crate::{codec_type, hash_impl};

use bitcoin_primitives::script::ScriptPubKeyBuf;
use dash_script::{PubKeyHash, Recipient};
use dash_types::codec::{BaseCodec, DecodeError, EncodeBuf};
use dash_types::type_id::TypeId;
use dash_types::{derive_bytes, impl_bytes};

/// Length of a compact recoverable ECDSA signature.
pub(crate) const COMPACT_SIGNATURE_LEN: usize = 65;

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

impl MasternodePayoutShare {
  /// Smallest share of the owner reward in basis points.
  pub const MIN_REWARD: u16 = 100;

  /// Whole owner reward in basis points.
  pub const MAX_REWARD: u16 = 10_000;
}

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

impl CollateralShare {
  /// Smallest contribution in duffs, 100 DASH.
  pub const MIN_AMOUNT: i64 = 100 * 100_000_000;
}

/// Most entries an owner payout list holds.
const MAX_PAYOUTS: usize = 8;

/// The single payout script of a version 1 or 2 payload as a payout list.
pub(crate) fn legacy_payout_list(script_payout: &ScriptPubKeyBuf) -> [MasternodePayoutShare; 1] {
  [MasternodePayoutShare {
    script_payout: script_payout.clone(),
    reward: MasternodePayoutShare::MAX_REWARD,
  }]
}

/// Checks an owner payout list. A payout may pay neither `owner`, when
/// given, nor `voting`.
pub(crate) fn check_payout_list(
  payouts: &[MasternodePayoutShare],
  owner: Option<&PubKeyHash>,
  voting: &PubKeyHash,
) -> Option<ProTxInvalid> {
  if payouts.is_empty() || payouts.len() > MAX_PAYOUTS {
    return Some(ProTxInvalid::BadPayoutCount { count: payouts.len() });
  }
  let mut total = 0u32;
  let mut scripts = BTreeSet::new();
  for payout in payouts {
    let reward = payout.reward;
    if !(MasternodePayoutShare::MIN_REWARD..=MasternodePayoutShare::MAX_REWARD).contains(&reward) {
      return Some(ProTxInvalid::BadPayoutReward { reward });
    }
    total += u32::from(reward);
    let recipient = Recipient::from_script(payout.script_payout.as_bytes());
    if !matches!(recipient, Some(Recipient::PubKeyHash(_) | Recipient::ScriptHash(_))) {
      return Some(ProTxInvalid::BadPayoutScript);
    }
    if !scripts.insert(payout.script_payout.as_bytes()) {
      return Some(ProTxInvalid::DuplicatePayoutScript);
    }
    if let Some(Recipient::PubKeyHash(hash)) = &recipient {
      if Some(hash) == owner || hash == voting {
        return Some(ProTxInvalid::PayoutKeyReuse);
      }
    }
  }
  (total != u32::from(MasternodePayoutShare::MAX_REWARD)).then_some(ProTxInvalid::BadPayoutRewardSum { total })
}

/// Most entries a list with a single-byte count holds.
pub(crate) const MAX_U8_LIST_LEN: usize = u8::MAX as usize;

/// Reads a list whose count is a single byte.
pub(crate) fn decode_u8_list<T: BaseCodec>(data: &mut &[u8]) -> Result<Vec<T>, DecodeError> {
  let count = u8::decode(data)?;
  (0..count).map(|_| T::decode(data)).collect()
}

/// Writes the single-byte count of a list.
///
/// The payload constructors cap every such list at 255 entries.
pub(crate) fn encode_u8_count(len: usize, buf: &mut impl EncodeBuf) {
  u8::try_from(len).unwrap_or(u8::MAX).encode(buf);
}

/// Writes a list whose count is a single byte.
pub(crate) fn encode_u8_list<T: BaseCodec>(items: &[T], buf: &mut impl EncodeBuf) {
  encode_u8_count(items.len(), buf);
  for item in items {
    item.encode(buf);
  }
}

#[cfg(test)]
mod tests {
  use super::{check_payout_list, CollateralShare, CompactSignature, MasternodePayoutShare};
  use crate::payload::ProTxInvalid;
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

  fn p2pkh(byte: u8) -> ScriptPubKeyBuf {
    let mut script = hex!("76a914").to_vec();
    script.extend([byte; 20]);
    script.extend(hex!("88ac"));
    ScriptPubKeyBuf::from_bytes(script)
  }

  fn p2sh(byte: u8) -> ScriptPubKeyBuf {
    let mut script = hex!("a914").to_vec();
    script.extend([byte; 20]);
    script.push(0x87);
    ScriptPubKeyBuf::from_bytes(script)
  }

  fn payout(script_payout: ScriptPubKeyBuf, reward: u16) -> MasternodePayoutShare {
    MasternodePayoutShare { script_payout, reward }
  }

  const OWNER: u8 = 0xa1;
  const VOTING: u8 = 0xa2;

  #[rstest]
  #[case::one(vec![payout(p2pkh(1), 10_000)], None)]
  #[case::p2sh(vec![payout(p2sh(1), 10_000)], None)]
  #[case::eight((1..=8).map(|i| payout(p2pkh(i), 1250)).collect(), None)]
  #[case::min_reward(vec![payout(p2pkh(1), 100), payout(p2pkh(2), 9900)], None)]
  #[case::empty(vec![], Some(ProTxInvalid::BadPayoutCount { count: 0 }))]
  #[case::nine((1..=9).map(|i| payout(p2pkh(i), 1000)).collect(), Some(ProTxInvalid::BadPayoutCount { count: 9 }))]
  #[case::reward_below_min(vec![payout(p2pkh(1), 99), payout(p2pkh(2), 9901)], Some(ProTxInvalid::BadPayoutReward { reward: 99 }))]
  #[case::reward_above_max(vec![payout(p2pkh(1), 10_001)], Some(ProTxInvalid::BadPayoutReward { reward: 10_001 }))]
  #[case::bad_script(vec![payout(ScriptPubKeyBuf::from_bytes(vec![0x51]), 10_000)], Some(ProTxInvalid::BadPayoutScript))]
  #[case::duplicate(vec![payout(p2pkh(1), 5000), payout(p2pkh(1), 5000)], Some(ProTxInvalid::DuplicatePayoutScript))]
  #[case::owner(vec![payout(p2pkh(OWNER), 10_000)], Some(ProTxInvalid::PayoutKeyReuse))]
  #[case::voting(vec![payout(p2pkh(VOTING), 10_000)], Some(ProTxInvalid::PayoutKeyReuse))]
  #[case::sum_short(vec![payout(p2pkh(1), 5000), payout(p2pkh(2), 4999)], Some(ProTxInvalid::BadPayoutRewardSum { total: 9999 }))]
  #[case::sum_over(vec![payout(p2pkh(1), 5000), payout(p2pkh(2), 5001)], Some(ProTxInvalid::BadPayoutRewardSum { total: 10_001 }))]
  fn payout_list_rules(#[case] payouts: Vec<MasternodePayoutShare>, #[case] expected: Option<ProTxInvalid>) {
    let owner = PubKeyHash::from_lendian([OWNER; 20]);
    let voting = PubKeyHash::from_lendian([VOTING; 20]);
    assert_eq!(check_payout_list(&payouts, Some(&owner), &voting), expected);
  }

  /// The entries are checked in order, ahead of the reward sum.
  #[rstest]
  fn payout_list_reports_the_first_failing_entry() {
    let voting = PubKeyHash::from_lendian([VOTING; 20]);
    let payouts = [payout(p2pkh(VOTING), 5000), payout(p2pkh(1), 50)];
    assert_eq!(
      check_payout_list(&payouts, None, &voting),
      Some(ProTxInvalid::PayoutKeyReuse)
    );
  }

  #[rstest]
  fn payout_list_without_an_owner_may_pay_any_other_key() {
    let voting = PubKeyHash::from_lendian([VOTING; 20]);
    let payouts = [payout(p2pkh(OWNER), 10_000)];
    assert_eq!(check_payout_list(&payouts, None, &voting), None);
  }

  #[rstest]
  #[case::count(ProTxInvalid::BadPayoutCount { count: 9 }, "bad-protx-payouts-count: 9")]
  #[case::reward(ProTxInvalid::BadPayoutReward { reward: 99 }, "bad-protx-payout-reward: 99")]
  #[case::duplicate(ProTxInvalid::DuplicatePayoutScript, "bad-protx-payee-dup")]
  #[case::sum(ProTxInvalid::BadPayoutRewardSum { total: 9999 }, "bad-protx-payout-reward-sum: 9999")]
  fn payout_list_reasons(#[case] error: ProTxInvalid, #[case] reason: &str) {
    assert_eq!(error.to_string(), reason);
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
