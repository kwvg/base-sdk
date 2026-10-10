//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! ProUpShareTx share reward update payload (type 11).

use super::InputsHash;
use crate::codec::codec_payload;
use crate::prelude::*;
use crate::TxHash;

use bitcoin_primitives::script::ScriptPubKeyBuf;
use dash_types::type_id::TypeId;

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

impl fmt::Display for ProUpShareTx {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "ProUpShareTx {{ v{}, share: {} }}", self.version, self.share_index)
  }
}

#[cfg(all(test, feature = "serde"))]
mod tests {
  use super::*;
  use crate::Transaction;

  use dash_dev::{assert_serde_rt, Corpus};
  use dash_types::codec::BaseCodec;
  use dash_types::Hashable;
  use rstest::rstest;

  fn corpus_items() -> BTreeMap<String, ProUpShareTx> {
    let corpus = Corpus::open(env!("CARGO_MANIFEST_DIR"), "proupsharetx");
    corpus.entries::<ProUpShareTx>("proupsharetx", |raw, item, label| {
      let tx = Transaction::decode(&mut &raw[..]);
      assert_eq!(tx.as_ref().map(|tx| tx.hash().to_string()), Ok(label.to_string()));
      let payload = tx.map(|tx| tx.extra_payload).unwrap_or_default();
      assert_eq!(
        ProUpShareTx::decode(&mut payload.as_slice()).as_ref(),
        Ok(item),
        "{label}"
      );
      let mut buf = Vec::new();
      item.encode(&mut buf);
      assert_eq!(buf, payload, "{label}");
    })
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
}
