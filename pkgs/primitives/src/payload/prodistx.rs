//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! ProDisTx shared masternode dissolution payload (type 10).

use super::protx::{decode_u8_list, encode_u8_list, MAX_U8_LIST_LEN};
use super::{payload_hash, CompactSignature, ProRegTx, ProTxInvalid};
use crate::codec::impl_payload;
use crate::prelude::*;
use crate::{hash_impl, Transaction, TxHash};

use dash_num::Hash256;
use dash_types::codec::{BaseCodec, DecodeError, EncodeBuf};
use dash_types::type_id::TypeId;
use dash_types::{Checkable, CompactSize, Numeric};

use core::fmt;

/// ProDisTx -- dissolve a shared masternode (type 10).
///
/// One signature, by the acting share's owner, dissolves unilaterally; one
/// per share, in share order, dissolves unanimously. Every version shares
/// one layout.
#[derive(Clone, Debug, Eq, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase", try_from = "__ProDisFields"))]
pub struct ProDisTx {
  /// Payload version.
  pub version: u16,
  /// ProTx hash identifying the masternode.
  pub pro_tx_hash: TxHash,
  /// Index of the share whose owner acts.
  pub actor_index: u16,
  sigs: Vec<CompactSignature>,
}

impl_payload!(ProDisTx);

impl BaseCodec for ProDisTx {
  fn decode(data: &mut &[u8]) -> Result<Self, DecodeError> {
    Ok(Self {
      version: u16::decode(data)?,
      pro_tx_hash: TxHash::decode(data)?,
      actor_index: u16::decode(data)?,
      sigs: decode_u8_list(data)?,
    })
  }

  fn encode(&self, buf: &mut impl EncodeBuf) {
    self.version.encode(buf);
    self.pro_tx_hash.encode(buf);
    self.actor_index.encode(buf);
    encode_u8_list(&self.sigs, buf);
  }
}

impl Checkable for ProDisTx {
  type Error = ProTxInvalid;

  fn check(&self) -> Option<Self::Error> {
    if self.version == 0 || self.version > Self::CURRENT_VERSION {
      return Some(ProTxInvalid::BadDissolveVersion { version: self.version });
    }
    let count = self.sigs.len();
    (count == 0 || count > ProRegTx::MAX_SHARES).then_some(ProTxInvalid::BadDissolveSigCount { count })
  }
}

hash_impl!(ProDisTx);

/// Prefix of the dissolution signing message.
const SIGN_PREFIX: [u8; 20] = *b"DashSharedMNDissolve";

impl ProDisTx {
  /// Highest payload version.
  pub const CURRENT_VERSION: u16 = 1;

  /// Builds a dissolution.
  ///
  /// # Errors
  ///
  /// Returns [`ProTxInvalid::BadDissolveSigCount`] for more than 255
  /// signatures, which the single-byte count cannot carry.
  pub fn new(
    version: u16,
    pro_tx_hash: TxHash,
    actor_index: u16,
    sigs: Vec<CompactSignature>,
  ) -> Result<Self, ProTxInvalid> {
    if sigs.len() > MAX_U8_LIST_LEN {
      return Err(ProTxInvalid::BadDissolveSigCount { count: sigs.len() });
    }
    Ok(Self {
      version,
      pro_tx_hash,
      actor_index,
      sigs,
    })
  }

  /// Signatures of the share owners.
  pub fn sigs(&self) -> &[CompactSignature] {
    &self.sigs
  }

  /// Hash every signature of the dissolution in `tx` signs. It commits to
  /// `sig_count`, the count `tx` carries, so a third party cannot switch the
  /// mode by adding or dropping signatures.
  pub fn sign_hash(&self, tx: &Transaction, sig_count: u8) -> Hash256 {
    payload_hash(|buf| {
      CompactSize::from(SIGN_PREFIX.len()).encode(buf);
      SIGN_PREFIX.encode(buf);
      self.version.encode(buf);
      tx.version.encode(buf);
      tx.tx_type.to_base().encode(buf);
      tx.lock_time.encode(buf);
      for input in &tx.inputs {
        input.prevout.encode(buf);
      }
      for input in &tx.inputs {
        input.sequence.encode(buf);
      }
      for output in &tx.outputs {
        output.encode(buf);
      }
      self.pro_tx_hash.encode(buf);
      self.actor_index.encode(buf);
      sig_count.encode(buf);
    })
  }
}

/// Field set that builds a deserialized dissolution through
/// [`ProDisTx::new`].
#[cfg(feature = "serde")]
#[derive(::serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct __ProDisFields {
  version: u16,
  pro_tx_hash: TxHash,
  actor_index: u16,
  sigs: Vec<CompactSignature>,
}

#[cfg(feature = "serde")]
impl TryFrom<__ProDisFields> for ProDisTx {
  type Error = ProTxInvalid;

  fn try_from(fields: __ProDisFields) -> Result<Self, Self::Error> {
    Self::new(fields.version, fields.pro_tx_hash, fields.actor_index, fields.sigs)
  }
}

impl fmt::Display for ProDisTx {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(
      f,
      "ProDisTx {{ v{}, actor: {}, sigs: {} }}",
      self.version,
      self.actor_index,
      self.sigs.len()
    )
  }
}

#[cfg(all(test, feature = "serde"))]
mod tests {
  use super::*;
  use crate::payload::protx::testing::{shared_registration, signer};

  use dash_dev::{assert_serde_rt, check_sptx, Corpus};
  use rstest::rstest;

  fn corpus_items() -> BTreeMap<String, ProDisTx> {
    Corpus::open(env!("CARGO_MANIFEST_DIR"), "prodistx").entries::<ProDisTx>("prodistx", check_sptx)
  }

  #[rstest]
  fn corpus_prodistx() {
    let items = corpus_items();
    assert_serde_rt("prodistx", &items);
    let counts: BTreeSet<usize> = items.values().map(|item| item.sigs().len()).collect();
    assert_eq!(counts, BTreeSet::from([1, 2, 8]));
  }

  #[rstest]
  #[case::zero(0)]
  #[case::past_current(2)]
  #[case::max(u16::MAX)]
  fn every_version_decodes_one_layout(#[case] version: u16) {
    for (label, mut item) in corpus_items() {
      item.version = version;
      let mut buf = Vec::new();
      item.encode(&mut buf);
      assert_eq!(buf.len(), 37 + 65 * item.sigs().len(), "{label}");
      assert_eq!(ProDisTx::decode(&mut buf.as_slice()), Ok(item), "{label}");
    }
  }

  #[rstest]
  fn signatures_fit_a_single_byte_count() {
    let pro_tx_hash = TxHash::default();
    let sig = CompactSignature::from_bytes([1; 65]);
    assert!(ProDisTx::new(1, pro_tx_hash, 0, vec![sig; 255]).is_ok());
    assert_eq!(
      ProDisTx::new(1, pro_tx_hash, 0, vec![sig; 256]),
      Err(ProTxInvalid::BadDissolveSigCount { count: 256 })
    );
    assert_eq!(
      ProTxInvalid::BadDissolveSigCount { count: 256 }.to_string(),
      "bad-prodis-sig-count: 256"
    );
  }

  #[rstest]
  #[case::zero(0, Some(ProTxInvalid::BadDissolveVersion { version: 0 }))]
  #[case::current(1, None)]
  #[case::past_current(2, Some(ProTxInvalid::BadDissolveVersion { version: 2 }))]
  fn version_is_one(#[case] version: u16, #[case] expected: Option<ProTxInvalid>) {
    for (label, mut item) in corpus_items() {
      item.version = version;
      assert_eq!(item.check(), expected, "{label}");
    }
  }

  #[rstest]
  #[case::none(0, Some(ProTxInvalid::BadDissolveSigCount { count: 0 }))]
  #[case::one(1, None)]
  #[case::eight(8, None)]
  #[case::nine(9, Some(ProTxInvalid::BadDissolveSigCount { count: 9 }))]
  fn one_to_eight_signatures(#[case] count: usize, #[case] expected: Option<ProTxInvalid>) {
    for (label, mut item) in corpus_items() {
      item.sigs = vec![CompactSignature::from_bytes([1; 65]); count];
      assert_eq!(item.check(), expected, "{label}");
    }
  }

  /// A version past the current one fails ahead of a bad signature count.
  #[rstest]
  fn version_is_checked_first() {
    for (label, mut item) in corpus_items() {
      item.version = 2;
      item.sigs.clear();
      assert_eq!(
        item.check(),
        Some(ProTxInvalid::BadDissolveVersion { version: 2 }),
        "{label}"
      );
    }
    assert_eq!(
      ProTxInvalid::BadDissolveVersion { version: 2 }.to_string(),
      "bad-prodis-version: 2"
    );
  }

  /// The corpus dissolutions, each in its transaction.
  fn corpus_transactions() -> Vec<(Transaction, ProDisTx)> {
    let corpus = Corpus::open(env!("CARGO_MANIFEST_DIR"), "prodistx");
    let mut txs = Vec::new();
    corpus.entries::<ProDisTx>("prodistx", |raw, item, label| {
      let tx = Transaction::decode(&mut &raw[..]);
      assert!(tx.is_ok(), "{label}");
      if let Ok(tx) = tx {
        txs.push((tx, item.clone()));
      }
    });
    txs
  }

  /// One signature recovers to the actor's share owner; several recover to
  /// every share owner in share order.
  #[rstest]
  fn share_owners_sign_the_sign_hash() {
    for (tx, item) in corpus_transactions() {
      let registration = shared_registration(&item.pro_tx_hash);
      assert!(registration.is_some(), "{}", item.pro_tx_hash);
      let owners: Vec<_> = registration
        .iter()
        .flat_map(|reg| reg.shares().iter().map(|(share, _)| Some(share.key_id_owner)))
        .collect();
      let count = u8::try_from(item.sigs().len()).unwrap_or(u8::MAX);
      let hash = item.sign_hash(&tx, count);
      let signers: Vec<_> = item.sigs().iter().map(|sig| signer(&hash, sig.as_bytes())).collect();
      if signers.len() == 1 {
        assert_eq!(signers[0], owners[usize::from(item.actor_index)]);
      } else {
        assert_eq!(signers, owners);
      }
    }
  }

  #[rstest]
  fn sign_hash_commits_to_the_signature_count() {
    for (tx, item) in corpus_transactions() {
      let count = u8::try_from(item.sigs().len()).unwrap_or(u8::MAX);
      assert_ne!(item.sign_hash(&tx, count), item.sign_hash(&tx, count + 1));
    }
  }
}
