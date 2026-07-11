//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! ProUpRegTx registrar-update payload (type 3).

use super::{InputsHash, ProTxInvalid};
use crate::codec::codec_payload;
use crate::prelude::*;
use crate::script::{KeyId, Script};
use crate::TxHash;

use dash_pkc::bls::{BlsPkBytes, BlsScIetf};
use dash_types::codec::Checkable;
use dash_types::TypeId;

use core::fmt;

/// ProUpRegTx -- update MN keys/payout (type 3).
///
/// - v1: LegacyBLS
/// - v2: BasicBLS
#[derive(Clone, Debug, Eq, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub struct ProUpRegTx {
  /// 1=LegacyBLS, 2=BasicBLS.
  pub version: u16,
  /// ProTx hash identifying the masternode.
  pub pro_tx_hash: TxHash,
  /// Reserved, always 0.
  pub mode: u16,
  /// Operator BLS public key (48 bytes).
  pub pub_key_operator: BlsPkBytes<BlsScIetf>,
  /// Voting key id (20 bytes).
  pub key_id_voting: KeyId,
  /// Payout script.
  pub script_payout: Script,
  /// Hash of all inputs.
  pub inputs_hash: InputsHash,
  /// Owner ECDSA signature (variable-length).
  #[cfg_attr(feature = "serde", serde(with = "dash_types::serialize::hex"))]
  pub vch_sig: Vec<u8>,
}

codec_payload!(ProUpRegTx {
  version,
  pro_tx_hash,
  mode,
  pub_key_operator,
  key_id_voting,
  script_payout,
  inputs_hash,
  vch_sig,
});

impl Checkable for ProUpRegTx {
  type Error = ProTxInvalid;

  fn check(&self) -> Option<Self::Error> {
    if self.version == 0 {
      return Some(ProTxInvalid::BadVersion { version: self.version });
    }

    if self.mode != 0 {
      return Some(ProTxInvalid::BadMode { mode: self.mode });
    }

    if self.pub_key_operator.is_null() {
      return Some(ProTxInvalid::NullKey);
    }
    if self.key_id_voting.is_null() {
      return Some(ProTxInvalid::NullKey);
    }

    let payout = self.script_payout.as_bytes();
    if !dash_script::is_p2pkh(payout) && !dash_script::is_p2sh(payout) {
      return Some(ProTxInvalid::BadPayoutScript);
    }

    None
  }
}

impl fmt::Display for ProUpRegTx {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "ProUpRegTx {{ v{} }}", self.version)
  }
}

#[cfg(all(test, feature = "serde"))]
mod tests {
  use super::*;

  use dash_dev::{assert_serde_rt, check_sptx, load_corpus_file, read_corpus};
  use rstest::rstest;

  #[rstest]
  fn corpus_proupregtx() {
    let text = load_corpus_file(env!("CARGO_MANIFEST_DIR"), "proupregtx");
    let items = read_corpus::<ProUpRegTx>(&text, "proupregtx", check_sptx);
    assert_serde_rt("proupregtx", &items);
  }
}
