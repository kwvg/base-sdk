//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! ProUpRegTx registrar-update payload (type 3).

use super::{decode_version, payload_hash, InputsHash, ProTxInvalid, PROTX_VERSION_EXT_ADDR};
use crate::codec::impl_payload;
use crate::prelude::*;
use crate::types::{BlsPubKey, BlsScheme};
use crate::TxHash;

use bitcoin_primitives::script::ScriptPubKeyBuf;
use dash_num::Hash256;
#[cfg(feature = "serde")]
use dash_pkc::bls::BLS_PK_LEN;
use dash_script::{PubKeyHash, Recipient};
use dash_types::codec::{BaseCodec, DecodeError, EncodeBuf};
use dash_types::type_id::TypeId;
use dash_types::Checkable;
use dash_types::Hashable;

use core::fmt;

/// ProUpRegTx -- update MN keys/payout (type 3).
///
/// - v1: LegacyBLS
/// - v2: BasicBLS
#[derive(Clone, Debug, Eq, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase", from = "__ProUpRegFields"))]
pub struct ProUpRegTx {
  /// 1=LegacyBLS, 2=BasicBLS.
  pub version: u16,
  /// ProTx hash identifying the masternode.
  pub pro_tx_hash: TxHash,
  /// Reserved, always 0.
  pub mode: u16,
  /// Operator BLS public key (48 bytes).
  pub pub_key_operator: BlsPubKey,
  /// Voting key id (20 bytes).
  pub key_id_voting: PubKeyHash,
  /// Payout script.
  pub script_payout: ScriptPubKeyBuf,
  /// Hash of all inputs.
  pub inputs_hash: InputsHash,
  /// Owner ECDSA signature (variable-length).
  #[cfg_attr(feature = "serde", serde(with = "dash_types::serialize::hex"))]
  pub vch_sig: Vec<u8>,
}

impl_payload!(ProUpRegTx);

impl BaseCodec for ProUpRegTx {
  fn decode(data: &mut &[u8]) -> Result<Self, DecodeError> {
    let version = decode_version(data)?;
    Ok(Self {
      version,
      pro_tx_hash: TxHash::decode(data)?,
      mode: u16::decode(data)?,
      pub_key_operator: BlsPubKey::decode(data, BlsScheme::from_protx_version(version))?,
      key_id_voting: PubKeyHash::decode(data)?,
      script_payout: ScriptPubKeyBuf::decode(data)?,
      inputs_hash: InputsHash::decode(data)?,
      vch_sig: Vec::decode(data)?,
    })
  }

  fn encode(&self, buf: &mut impl EncodeBuf) {
    self.encode_unsigned(buf);
    self.vch_sig.encode(buf);
  }
}

impl Checkable for ProUpRegTx {
  type Error = ProTxInvalid;

  fn check(&self) -> Option<Self::Error> {
    if self.version == 0 || self.version > PROTX_VERSION_EXT_ADDR {
      return Some(ProTxInvalid::BadVersion { version: self.version });
    }

    if self.mode != 0 {
      return Some(ProTxInvalid::BadMode { mode: self.mode });
    }

    // A non-canonical operator key is an invalid key, reported as null.
    if self.pub_key_operator.is_null() || !self.pub_key_operator.is_canonical() {
      return Some(ProTxInvalid::NullKey);
    }
    if self.key_id_voting.is_null() {
      return Some(ProTxInvalid::NullKey);
    }

    let payout = self.script_payout.as_bytes();
    if !matches!(
      Recipient::from_script(payout),
      Some(Recipient::PubKeyHash(_) | Recipient::ScriptHash(_))
    ) {
      return Some(ProTxInvalid::BadPayoutScript);
    }

    None
  }
}

/// The hash leaves out the owner signature, which signs the hash.
impl Hashable for ProUpRegTx {
  type Hash = Hash256;

  fn hash(&self) -> Hash256 {
    payload_hash(|buf| self.encode_unsigned(buf))
  }
}

impl ProUpRegTx {
  fn encode_unsigned(&self, buf: &mut impl EncodeBuf) {
    self.version.encode(buf);
    self.pro_tx_hash.encode(buf);
    self.mode.encode(buf);
    self.pub_key_operator.encode(buf);
    self.key_id_voting.encode(buf);
    self.script_payout.encode(buf);
    self.inputs_hash.encode(buf);
  }
}

/// Field set that tags the operator key from the payload version.
#[cfg(feature = "serde")]
#[derive(::serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct __ProUpRegFields {
  version: u16,
  pro_tx_hash: TxHash,
  mode: u16,
  #[serde(deserialize_with = "crate::serialize::bls::pk_bytes")]
  pub_key_operator: [u8; BLS_PK_LEN],
  key_id_voting: PubKeyHash,
  script_payout: ScriptPubKeyBuf,
  inputs_hash: InputsHash,
  #[serde(with = "dash_types::serialize::hex")]
  vch_sig: Vec<u8>,
}

#[cfg(feature = "serde")]
impl From<__ProUpRegFields> for ProUpRegTx {
  fn from(fields: __ProUpRegFields) -> Self {
    Self {
      version: fields.version,
      pro_tx_hash: fields.pro_tx_hash,
      mode: fields.mode,
      pub_key_operator: BlsPubKey::from_bytes(fields.pub_key_operator, BlsScheme::from_protx_version(fields.version)),
      key_id_voting: fields.key_id_voting,
      script_payout: fields.script_payout,
      inputs_hash: fields.inputs_hash,
      vch_sig: fields.vch_sig,
    }
  }
}

impl fmt::Display for ProUpRegTx {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "ProUpRegTx {{ v{} }}", self.version)
  }
}

#[cfg(all(test, feature = "serde"))]
#[expect(clippy::unwrap_used, reason = "test code")]
mod tests {
  use super::*;

  use dash_dev::{assert_serde_rt, check_sptx, from_json, to_json, Corpus};
  use rstest::rstest;

  #[rstest]
  fn corpus_proupregtx() {
    let corpus = Corpus::open(env!("CARGO_MANIFEST_DIR"), "proupregtx");
    let items = corpus.entries::<ProUpRegTx>("proupregtx", check_sptx);
    assert_serde_rt("proupregtx", &items);
  }

  /// The corpus holds the registration this update refers to. The owner
  /// signature recovers to the registered owner key over the hash without
  /// the signature, and to another key over the hash with it.
  #[rstest]
  fn owner_signature_recovers_over_the_payload_hash() {
    use crate::ProRegTx;

    use dash_pkc::ecdsa::{EcdsaPkBytes, EcdsaPublicKey, EcdsaRecSigBytes, EcdsaRecSignature};
    use dash_types::Hashable;

    let registrations =
      Corpus::open(env!("CARGO_MANIFEST_DIR"), "proregtx").entries::<ProRegTx>("proregtx", |_, _, _| {});
    let updates =
      Corpus::open(env!("CARGO_MANIFEST_DIR"), "proupregtx").entries::<ProUpRegTx>("proupregtx", |_, _, _| {});
    let (update, registration) = updates
      .values()
      .find_map(|update| {
        registrations
          .get(&update.pro_tx_hash.to_string())
          .map(|reg| (update, reg))
      })
      .unwrap();

    let sig = EcdsaRecSigBytes::from_raw(update.vch_sig.as_slice().try_into().unwrap()).unwrap();
    let sig = EcdsaRecSignature::try_from(sig).unwrap();
    let owner = |hash: [u8; 32]| EcdsaPkBytes::from(EcdsaPublicKey::recover(&hash, &sig).unwrap()).hash();

    assert_eq!(owner(*update.hash().as_bytes()), registration.key_id_owner);
    let mut signed = Vec::new();
    update.encode(&mut signed);
    let with_sig = bitcoin_hashes::sha256d::Hash::hash(&signed).to_byte_array();
    assert_ne!(owner(with_sig), registration.key_id_owner);
  }

  #[rstest]
  #[case::zero(0)]
  #[case::past_ext_addr(4)]
  #[case::max(u16::MAX)]
  fn version_outside_one_to_three_is_rejected(#[case] version: u16) {
    let corpus = Corpus::open(env!("CARGO_MANIFEST_DIR"), "proupregtx");
    let mut item = corpus
      .entries::<ProUpRegTx>("proupregtx", |_, _, _| {})
      .into_values()
      .next()
      .unwrap();
    item.version = version;
    assert_eq!(item.check(), Some(ProTxInvalid::BadVersion { version }));
  }

  /// Payload versions 1 and 2 share a layout, so a corpus payload serves for
  /// both once its version and tag change.
  #[rstest]
  #[case::legacy(1, BlsScheme::Legacy)]
  #[case::basic(2, BlsScheme::Basic)]
  fn pub_key_operator_is_tagged_from_the_version(#[case] version: u16, #[case] scheme: BlsScheme) {
    let corpus = Corpus::open(env!("CARGO_MANIFEST_DIR"), "proupregtx");
    let mut item = corpus
      .entries::<ProUpRegTx>("proupregtx", |_, _, _| {})
      .into_values()
      .next()
      .unwrap();
    item.version = version;
    item.pub_key_operator = BlsPubKey::from_bytes(*item.pub_key_operator.as_bytes(), scheme);

    let mut buf = Vec::new();
    item.encode(&mut buf);
    let decoded = ProUpRegTx::decode(&mut buf.as_slice()).unwrap();
    assert_eq!(decoded.pub_key_operator.scheme(), scheme);
    assert_eq!(decoded, item);
    assert_eq!(from_json::<ProUpRegTx>(&to_json(&item)), item);
  }

  #[rstest]
  fn non_canonical_operator_key_is_a_null_key() {
    let corpus = Corpus::open(env!("CARGO_MANIFEST_DIR"), "proupregtx");
    let mut item = corpus
      .entries::<ProUpRegTx>("proupregtx", |_, _, _| {})
      .into_values()
      .next()
      .unwrap();
    assert_eq!(item.check(), None);
    item.pub_key_operator = item.pub_key_operator.corrupted();
    assert_eq!(item.check(), Some(ProTxInvalid::NullKey));
  }
}
