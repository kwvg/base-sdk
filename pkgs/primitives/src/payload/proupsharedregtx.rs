//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! ProUpSharedRegTx shared registrar update payload (type 12).

use super::protx::{decode_u8_list, encode_u8_list, MAX_U8_LIST_LEN};
use super::{CompactSignature, InputsHash, ProTxInvalid};
use crate::codec::impl_payload;
use crate::prelude::*;
use crate::types::{BlsPubKey, BlsScheme};
use crate::{hash_impl, TxHash};

use dash_pkc::bls::BLS_PK_LEN;
use dash_script::PubKeyHash;
use dash_types::codec::{BaseCodec, DecodeError, EncodeBuf};
use dash_types::type_id::TypeId;

use core::fmt;

/// ProUpSharedRegTx -- update the operator and voting keys of a shared
/// masternode (type 12).
///
/// Every share's owner signs, in share order. The operator key is always in
/// the basic scheme.
#[derive(Clone, Debug, Eq, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
#[cfg_attr(
  feature = "serde",
  serde(rename_all = "camelCase", try_from = "__ProUpSharedRegFields")
)]
pub struct ProUpSharedRegTx {
  /// Payload version.
  pub version: u16,
  /// ProTx hash identifying the masternode.
  pub pro_tx_hash: TxHash,
  pub_key_operator: BlsPubKey,
  /// Voting key id (20 bytes).
  pub key_id_voting: PubKeyHash,
  /// Hash of all inputs.
  pub inputs_hash: InputsHash,
  sigs: Vec<CompactSignature>,
}

impl_payload!(ProUpSharedRegTx);

impl BaseCodec for ProUpSharedRegTx {
  fn decode(data: &mut &[u8]) -> Result<Self, DecodeError> {
    Ok(Self {
      version: u16::decode(data)?,
      pro_tx_hash: TxHash::decode(data)?,
      pub_key_operator: BlsPubKey::decode(data, BlsScheme::Basic)?,
      key_id_voting: PubKeyHash::decode(data)?,
      inputs_hash: InputsHash::decode(data)?,
      sigs: decode_u8_list(data)?,
    })
  }

  fn encode(&self, buf: &mut impl EncodeBuf) {
    self.version.encode(buf);
    self.pro_tx_hash.encode(buf);
    self.pub_key_operator.encode(buf);
    self.key_id_voting.encode(buf);
    self.inputs_hash.encode(buf);
    encode_u8_list(&self.sigs, buf);
  }
}

hash_impl!(ProUpSharedRegTx);

impl ProUpSharedRegTx {
  /// Builds a shared registrar update with `pub_key_operator` in the basic
  /// scheme.
  ///
  /// # Errors
  ///
  /// Returns [`ProTxInvalid::BadSharedRegSigCount`] for more than 255
  /// signatures, which the single-byte count cannot carry.
  pub fn new(
    version: u16,
    pro_tx_hash: TxHash,
    pub_key_operator: [u8; BLS_PK_LEN],
    key_id_voting: PubKeyHash,
    inputs_hash: InputsHash,
    sigs: Vec<CompactSignature>,
  ) -> Result<Self, ProTxInvalid> {
    if sigs.len() > MAX_U8_LIST_LEN {
      return Err(ProTxInvalid::BadSharedRegSigCount { count: sigs.len() });
    }
    Ok(Self {
      version,
      pro_tx_hash,
      pub_key_operator: BlsPubKey::from_bytes(pub_key_operator, BlsScheme::Basic),
      key_id_voting,
      inputs_hash,
      sigs,
    })
  }

  /// Operator BLS public key, in the basic scheme.
  pub const fn pub_key_operator(&self) -> &BlsPubKey {
    &self.pub_key_operator
  }

  /// Signatures of the share owners, in share order.
  pub fn sigs(&self) -> &[CompactSignature] {
    &self.sigs
  }
}

/// Field set that builds a deserialized update through
/// [`ProUpSharedRegTx::new`].
#[cfg(feature = "serde")]
#[derive(::serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct __ProUpSharedRegFields {
  version: u16,
  pro_tx_hash: TxHash,
  #[serde(deserialize_with = "crate::serialize::bls::pk_bytes")]
  pub_key_operator: [u8; BLS_PK_LEN],
  key_id_voting: PubKeyHash,
  inputs_hash: InputsHash,
  sigs: Vec<CompactSignature>,
}

#[cfg(feature = "serde")]
impl TryFrom<__ProUpSharedRegFields> for ProUpSharedRegTx {
  type Error = ProTxInvalid;

  fn try_from(fields: __ProUpSharedRegFields) -> Result<Self, Self::Error> {
    Self::new(
      fields.version,
      fields.pro_tx_hash,
      fields.pub_key_operator,
      fields.key_id_voting,
      fields.inputs_hash,
      fields.sigs,
    )
  }
}

impl fmt::Display for ProUpSharedRegTx {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "ProUpSharedRegTx {{ v{}, sigs: {} }}", self.version, self.sigs.len())
  }
}

#[cfg(all(test, feature = "serde"))]
mod tests {
  use super::*;
  use crate::Transaction;

  use dash_dev::{assert_serde_rt, Corpus};
  use dash_types::Hashable;
  use rstest::rstest;

  fn corpus_items() -> BTreeMap<String, ProUpSharedRegTx> {
    let corpus = Corpus::open(env!("CARGO_MANIFEST_DIR"), "proupsharedregtx");
    corpus.entries::<ProUpSharedRegTx>("proupsharedregtx", |raw, item, label| {
      let tx = Transaction::decode(&mut &raw[..]);
      assert_eq!(tx.as_ref().map(|tx| tx.hash().to_string()), Ok(label.to_string()));
      let payload = tx.map(|tx| tx.extra_payload).unwrap_or_default();
      assert_eq!(
        ProUpSharedRegTx::decode(&mut payload.as_slice()).as_ref(),
        Ok(item),
        "{label}"
      );
      let mut buf = Vec::new();
      item.encode(&mut buf);
      assert_eq!(buf, payload, "{label}");
    })
  }

  #[rstest]
  fn corpus_proupsharedregtx() {
    let items = corpus_items();
    assert_serde_rt("proupsharedregtx", &items);
    let counts: BTreeSet<usize> = items.values().map(|item| item.sigs().len()).collect();
    assert_eq!(counts, BTreeSet::from([2, 8]));
    assert!(items
      .values()
      .all(|item| item.pub_key_operator().scheme() == BlsScheme::Basic));
  }

  #[rstest]
  fn signatures_fit_a_single_byte_count() {
    for (label, item) in corpus_items() {
      let rebuilt = |count: usize| {
        let sigs = vec![CompactSignature::from_bytes([1; 65]); count];
        ProUpSharedRegTx::new(
          item.version,
          item.pro_tx_hash,
          *item.pub_key_operator.as_bytes(),
          item.key_id_voting,
          item.inputs_hash,
          sigs,
        )
      };
      assert!(rebuilt(255).is_ok(), "{label}");
      assert_eq!(
        rebuilt(256),
        Err(ProTxInvalid::BadSharedRegSigCount { count: 256 }),
        "{label}"
      );
    }
    assert_eq!(
      ProTxInvalid::BadSharedRegSigCount { count: 256 }.to_string(),
      "bad-proupsharedreg-sig-count: 256"
    );
  }
}
