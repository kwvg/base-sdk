//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! ProUpShareTx share reward update payload (type 11).

use super::protx::COMPACT_SIGNATURE_LEN;
use super::{InputsHash, ProTxInvalid};
use crate::codec::codec_payload;
use crate::prelude::*;
use crate::TxHash;

use bitcoin_primitives::script::ScriptPubKeyBuf;
use dash_script::Recipient;
use dash_types::type_id::TypeId;
use dash_types::Checkable;

use core::fmt;

/// ProUpShareTx -- update the reward script of one collateral share
/// (type 11).
#[derive(Clone, Debug, Eq, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub struct ProUpShareTx {
  /// Payload version.
  pub version: u16,
  /// ProTx hash identifying the masternode.
  pub pro_tx_hash: TxHash,
  /// Index of the share whose reward script changes.
  pub share_index: u16,
  /// New reward script of the share.
  pub script_reward: ScriptPubKeyBuf,
  /// Hash of all inputs.
  pub inputs_hash: InputsHash,
  /// Compact ECDSA signature of the share's owner, decoded at any length.
  #[cfg_attr(feature = "serde", serde(with = "dash_types::serialize::hex"))]
  pub vch_sig: Vec<u8>,
}

codec_payload!(ProUpShareTx {
  version,
  pro_tx_hash,
  share_index,
  script_reward,
  inputs_hash,
  vch_sig
});

impl Checkable for ProUpShareTx {
  type Error = ProTxInvalid;

  fn check(&self) -> Option<Self::Error> {
    if self.version == 0 || self.version > Self::CURRENT_VERSION {
      return Some(ProTxInvalid::BadShareUpdateVersion { version: self.version });
    }
    if self.vch_sig.len() != COMPACT_SIGNATURE_LEN {
      return Some(ProTxInvalid::BadShareUpdateSigSize {
        size: self.vch_sig.len(),
      });
    }
    let recipient = Recipient::from_script(self.script_reward.as_bytes());
    (!matches!(recipient, Some(Recipient::PubKeyHash(_) | Recipient::ScriptHash(_))))
      .then_some(ProTxInvalid::BadShareUpdatePayee)
  }
}

impl ProUpShareTx {
  /// Highest payload version.
  pub const CURRENT_VERSION: u16 = 1;
}

impl fmt::Display for ProUpShareTx {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "ProUpShareTx {{ v{}, share: {} }}", self.version, self.share_index)
  }
}

#[cfg(all(test, feature = "serde"))]
mod tests {
  use super::*;

  use dash_dev::{assert_serde_rt, check_sptx, Corpus};
  use dash_types::codec::BaseCodec;
  use hex_conservative::hex;
  use rstest::rstest;

  fn corpus_items() -> BTreeMap<String, ProUpShareTx> {
    Corpus::open(env!("CARGO_MANIFEST_DIR"), "proupsharetx").entries::<ProUpShareTx>("proupsharetx", check_sptx)
  }

  #[rstest]
  fn corpus_proupsharetx() {
    let items = corpus_items();
    assert_serde_rt("proupsharetx", &items);
    assert!(items.values().all(|item| item.vch_sig.len() == 65));
  }

  /// A signature of the wrong length decodes, so checks can report it.
  #[rstest]
  #[case::empty(0)]
  #[case::short(64)]
  #[case::long(66)]
  fn signature_of_any_length_decodes(#[case] len: usize) {
    for (label, mut item) in corpus_items() {
      item.vch_sig = vec![0x1f; len];
      let mut buf = Vec::new();
      item.encode(&mut buf);
      assert_eq!(ProUpShareTx::decode(&mut buf.as_slice()), Ok(item), "{label}");
    }
  }

  #[rstest]
  #[case::zero(0, Some(ProTxInvalid::BadShareUpdateVersion { version: 0 }))]
  #[case::current(1, None)]
  #[case::past_current(2, Some(ProTxInvalid::BadShareUpdateVersion { version: 2 }))]
  fn version_is_one(#[case] version: u16, #[case] expected: Option<ProTxInvalid>) {
    for (label, mut item) in corpus_items() {
      item.version = version;
      assert_eq!(item.check(), expected, "{label}");
    }
    assert_eq!(
      ProTxInvalid::BadShareUpdateVersion { version: 2 }.to_string(),
      "bad-proupshare-version: 2"
    );
  }

  #[rstest]
  #[case::empty(0)]
  #[case::short(64)]
  #[case::long(66)]
  fn signature_is_65_bytes(#[case] len: usize) {
    for (label, mut item) in corpus_items() {
      item.vch_sig = vec![0x1f; len];
      assert_eq!(
        item.check(),
        Some(ProTxInvalid::BadShareUpdateSigSize { size: len }),
        "{label}"
      );
    }
    assert_eq!(
      ProTxInvalid::BadShareUpdateSigSize { size: 64 }.to_string(),
      "bad-proupshare-sig-size: 64"
    );
  }

  #[rstest]
  #[case::p2pkh(hex!("76a914111111111111111111111111111111111111111188ac").to_vec(), None)]
  #[case::p2sh(hex!("a914111111111111111111111111111111111111111187").to_vec(), None)]
  #[case::empty(vec![], Some(ProTxInvalid::BadShareUpdatePayee))]
  #[case::op_true(vec![0x51], Some(ProTxInvalid::BadShareUpdatePayee))]
  #[case::op_return(vec![0x6a], Some(ProTxInvalid::BadShareUpdatePayee))]
  fn reward_pays_a_key_or_script_hash(#[case] script: Vec<u8>, #[case] expected: Option<ProTxInvalid>) {
    for (label, mut item) in corpus_items() {
      item.script_reward = ScriptPubKeyBuf::from_bytes(script.clone());
      assert_eq!(item.check(), expected, "{label}");
    }
    assert_eq!(ProTxInvalid::BadShareUpdatePayee.to_string(), "bad-proupshare-payee");
  }

  /// The version fails ahead of the signature size, and the signature size
  /// ahead of the payee.
  #[rstest]
  fn version_then_signature_then_payee() {
    for (label, mut item) in corpus_items() {
      item.script_reward = ScriptPubKeyBuf::new();
      item.vch_sig.clear();
      assert_eq!(
        item.check(),
        Some(ProTxInvalid::BadShareUpdateSigSize { size: 0 }),
        "{label}"
      );
      item.version = 0;
      assert_eq!(
        item.check(),
        Some(ProTxInvalid::BadShareUpdateVersion { version: 0 }),
        "{label}"
      );
    }
  }
}
