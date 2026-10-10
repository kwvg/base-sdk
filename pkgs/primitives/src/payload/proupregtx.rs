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
///
/// The version-coupled fields are private, so [`ProUpRegTx::new`] keeps them
/// in step with the version.
#[derive(Clone, Debug, Eq, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase", from = "__ProUpRegFields"))]
pub struct ProUpRegTx {
  version: u16,
  /// ProTx hash identifying the masternode.
  pub pro_tx_hash: TxHash,
  /// Reserved, always 0.
  pub mode: u16,
  pub_key_operator: BlsPubKey,
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
  /// Builds a registrar update. The version selects the scheme of
  /// `pub_key_operator`.
  #[expect(clippy::too_many_arguments, reason = "one argument per wire field")]
  pub fn new(
    version: u16,
    pro_tx_hash: TxHash,
    mode: u16,
    pub_key_operator: [u8; BLS_PK_LEN],
    key_id_voting: PubKeyHash,
    script_payout: ScriptPubKeyBuf,
    inputs_hash: InputsHash,
    vch_sig: Vec<u8>,
  ) -> Self {
    Self {
      version,
      pro_tx_hash,
      mode,
      pub_key_operator: BlsPubKey::from_bytes(pub_key_operator, BlsScheme::from_protx_version(version)),
      key_id_voting,
      script_payout,
      inputs_hash,
      vch_sig,
    }
  }

  /// Payload version.
  pub const fn version(&self) -> u16 {
    self.version
  }

  /// Operator BLS public key, in the scheme the version selects.
  pub const fn pub_key_operator(&self) -> &BlsPubKey {
    &self.pub_key_operator
  }

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

/// Field set that builds a deserialized update through [`ProUpRegTx::new`].
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
    Self::new(
      fields.version,
      fields.pro_tx_hash,
      fields.mode,
      fields.pub_key_operator,
      fields.key_id_voting,
      fields.script_payout,
      fields.inputs_hash,
      fields.vch_sig,
    )
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

  use dash_dev::{assert_serde_rt, check_sptx, from_json, to_json, Corpus};
  use rstest::rstest;

  fn corpus_items() -> BTreeMap<String, ProUpRegTx> {
    Corpus::open(env!("CARGO_MANIFEST_DIR"), "proupregtx").entries::<ProUpRegTx>("proupregtx", |_, _, _| {})
  }

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
    let updates = corpus_items();
    let pair = updates.values().find_map(|update| {
      registrations
        .get(&update.pro_tx_hash.to_string())
        .map(|reg| (update, reg))
    });
    assert!(pair.is_some());
    let Some((update, registration)) = pair else {
      return;
    };

    let sig = <[u8; 65]>::try_from(update.vch_sig.as_slice())
      .ok()
      .and_then(EcdsaRecSigBytes::from_raw)
      .and_then(|bytes| EcdsaRecSignature::try_from(bytes).ok());
    assert!(sig.is_some());
    let Some(sig) = sig else {
      return;
    };
    let owner = |hash: [u8; 32]| {
      EcdsaPublicKey::recover(&hash, &sig)
        .ok()
        .map(|key| EcdsaPkBytes::from(key).hash())
    };

    assert_eq!(owner(*update.hash().as_bytes()), Some(registration.key_id_owner));
    let mut signed = Vec::new();
    update.encode(&mut signed);
    let with_sig = bitcoin_hashes::sha256d::Hash::hash(&signed).to_byte_array();
    assert_ne!(owner(with_sig), Some(registration.key_id_owner));
  }

  #[rstest]
  #[case::zero(0)]
  #[case::past_ext_addr(4)]
  #[case::max(u16::MAX)]
  fn version_outside_one_to_three_is_rejected(#[case] version: u16) {
    for (label, mut item) in corpus_items() {
      item.version = version;
      assert_eq!(item.check(), Some(ProTxInvalid::BadVersion { version }), "{label}");
    }
  }

  /// Payload versions 1 and 2 share a layout, so a corpus payload serves for
  /// both once its version changes.
  #[rstest]
  #[case::legacy(1, BlsScheme::Legacy)]
  #[case::basic(2, BlsScheme::Basic)]
  fn pub_key_operator_is_tagged_from_the_version(#[case] version: u16, #[case] scheme: BlsScheme) {
    for (label, item) in corpus_items() {
      let item = ProUpRegTx::new(
        version,
        item.pro_tx_hash,
        item.mode,
        *item.pub_key_operator.as_bytes(),
        item.key_id_voting,
        item.script_payout,
        item.inputs_hash,
        item.vch_sig,
      );
      assert_eq!((item.version(), item.pub_key_operator().scheme()), (version, scheme));

      let mut buf = Vec::new();
      item.encode(&mut buf);
      assert_eq!(ProUpRegTx::decode(&mut buf.as_slice()).as_ref(), Ok(&item), "{label}");
      assert_eq!(from_json::<ProUpRegTx>(&to_json(&item)), item, "{label}");
    }
  }

  #[rstest]
  fn non_canonical_operator_key_is_a_null_key() {
    for (label, mut item) in corpus_items() {
      assert_eq!(item.check(), None, "{label}");
      item.pub_key_operator = item.pub_key_operator.corrupted();
      assert_eq!(item.check(), Some(ProTxInvalid::NullKey), "{label}");
    }
  }
}
