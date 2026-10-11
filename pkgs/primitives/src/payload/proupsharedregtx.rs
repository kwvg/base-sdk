//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! ProUpSharedRegTx shared registrar update payload (type 12).

use super::protx::{decode_u8_list, encode_u8_list, MAX_U8_LIST_LEN};
use super::{payload_hash, CompactSignature, InputsHash, ProRegTx, ProTxInvalid};
use crate::codec::impl_payload;
use crate::prelude::*;
use crate::types::{BlsPubKey, BlsScheme};
use crate::TxHash;

use dash_num::Hash256;
use dash_pkc::bls::BLS_PK_LEN;
use dash_script::PubKeyHash;
use dash_types::codec::{BaseCodec, DecodeError, EncodeBuf};
use dash_types::type_id::TypeId;
use dash_types::{Checkable, Hashable};

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
    self.encode_unsigned(buf);
    encode_u8_list(&self.sigs, buf);
  }
}

impl Checkable for ProUpSharedRegTx {
  type Error = ProTxInvalid;

  fn check(&self) -> Option<Self::Error> {
    if self.version == 0 || self.version > Self::CURRENT_VERSION {
      return Some(ProTxInvalid::BadSharedRegVersion { version: self.version });
    }
    // A non-canonical operator key is an invalid key, reported as null.
    if self.pub_key_operator.is_null() || !self.pub_key_operator.is_canonical() || self.key_id_voting.is_null() {
      return Some(ProTxInvalid::NullKey);
    }
    let count = self.sigs.len();
    (count == 0 || count > ProRegTx::MAX_SHARES).then_some(ProTxInvalid::BadSharedRegSigCount { count })
  }
}

/// The hash leaves out the owner signatures and their count, since every
/// owner signs the hash.
impl Hashable for ProUpSharedRegTx {
  type Hash = Hash256;

  fn hash(&self) -> Hash256 {
    payload_hash(|buf| self.encode_unsigned(buf))
  }
}

impl ProUpSharedRegTx {
  /// Highest payload version.
  pub const CURRENT_VERSION: u16 = 1;

  fn encode_unsigned(&self, buf: &mut impl EncodeBuf) {
    self.version.encode(buf);
    self.pro_tx_hash.encode(buf);
    self.pub_key_operator.encode(buf);
    self.key_id_voting.encode(buf);
    self.inputs_hash.encode(buf);
  }

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
  use crate::payload::protx::testing::{shared_registration, signer};

  use dash_dev::{assert_serde_rt, check_sptx, Corpus};
  use rstest::rstest;

  fn corpus_items() -> BTreeMap<String, ProUpSharedRegTx> {
    let corpus = Corpus::open(env!("CARGO_MANIFEST_DIR"), "proupsharedregtx");
    corpus.entries::<ProUpSharedRegTx>("proupsharedregtx", check_sptx)
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

  #[rstest]
  #[case::zero(0, Some(ProTxInvalid::BadSharedRegVersion { version: 0 }))]
  #[case::current(1, None)]
  #[case::past_current(2, Some(ProTxInvalid::BadSharedRegVersion { version: 2 }))]
  fn version_is_one(#[case] version: u16, #[case] expected: Option<ProTxInvalid>) {
    for (label, mut item) in corpus_items() {
      item.version = version;
      assert_eq!(item.check(), expected, "{label}");
    }
    assert_eq!(
      ProTxInvalid::BadSharedRegVersion { version: 2 }.to_string(),
      "bad-proupsharedreg-version: 2"
    );
  }

  #[rstest]
  #[case::null_operator(|t: &mut ProUpSharedRegTx| t.pub_key_operator = BlsPubKey::from_bytes([0; BLS_PK_LEN], BlsScheme::Basic))]
  #[case::corrupted_operator(|t: &mut ProUpSharedRegTx| t.pub_key_operator = t.pub_key_operator.corrupted())]
  #[case::null_voting(|t: &mut ProUpSharedRegTx| t.key_id_voting = PubKeyHash::default())]
  fn keys_must_be_valid(#[case] edit: fn(&mut ProUpSharedRegTx)) {
    for (label, mut item) in corpus_items() {
      edit(&mut item);
      assert_eq!(item.check(), Some(ProTxInvalid::NullKey), "{label}");
    }
  }

  #[rstest]
  #[case::none(0, Some(ProTxInvalid::BadSharedRegSigCount { count: 0 }))]
  #[case::one(1, None)]
  #[case::eight(8, None)]
  #[case::nine(9, Some(ProTxInvalid::BadSharedRegSigCount { count: 9 }))]
  fn one_to_eight_signatures(#[case] count: usize, #[case] expected: Option<ProTxInvalid>) {
    for (label, mut item) in corpus_items() {
      item.sigs = vec![CompactSignature::from_bytes([1; 65]); count];
      assert_eq!(item.check(), expected, "{label}");
    }
  }

  /// The version fails ahead of a null key, and a null key ahead of a bad
  /// signature count.
  #[rstest]
  fn version_then_keys_then_signature_count() {
    for (label, mut item) in corpus_items() {
      item.sigs.clear();
      item.key_id_voting = PubKeyHash::default();
      assert_eq!(item.check(), Some(ProTxInvalid::NullKey), "{label}");
      item.version = 2;
      assert_eq!(
        item.check(),
        Some(ProTxInvalid::BadSharedRegVersion { version: 2 }),
        "{label}"
      );
    }
  }

  /// Each corpus signature recovers, over the hash, to the owner of the share
  /// at its position.
  #[rstest]
  fn every_owner_signs_the_hash_in_share_order() {
    for (label, item) in corpus_items() {
      let registration = shared_registration(&item.pro_tx_hash);
      assert!(registration.is_some(), "{label}");
      let owners: Vec<_> = registration
        .iter()
        .flat_map(|reg| reg.shares().iter().map(|(share, _)| Some(share.key_id_owner)))
        .collect();
      let signers: Vec<_> = item
        .sigs()
        .iter()
        .map(|sig| signer(&item.hash(), sig.as_bytes()))
        .collect();
      assert_eq!(signers, owners, "{label}");
    }
  }

  #[rstest]
  fn hash_leaves_out_the_signatures_and_their_count() {
    for (label, mut item) in corpus_items() {
      let hash = item.hash();
      item.sigs.clear();
      assert_eq!(item.hash(), hash, "{label}");
      item.key_id_voting = PubKeyHash::default();
      assert_ne!(item.hash(), hash, "{label}");
    }
  }
}
