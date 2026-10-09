//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! ProUpRevTx revocation payload (type 4).

use super::{InputsHash, ProTxInvalid};
use crate::codec::impl_payload;
use crate::support::RevocationReason;
use crate::types::{BlsScheme, BlsSig};
use crate::{hash_impl, TxHash};

#[cfg(feature = "serde")]
use dash_pkc::bls::BLS_SIG_LEN;
use dash_types::codec::{BaseCodec, DecodeError, EncodeBuf};
use dash_types::type_id::TypeId;
use dash_types::Checkable;

use core::fmt;

/// ProUpRevTx -- revoke a masternode (type 4).
///
/// - v1: LegacyBLS
/// - v2: BasicBLS
#[derive(Clone, Debug, Eq, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase", from = "__ProUpRevFields"))]
pub struct ProUpRevTx {
  /// 1=LegacyBLS, 2=BasicBLS.
  pub version: u16,
  /// ProTx hash identifying the masternode.
  pub pro_tx_hash: TxHash,
  /// Revocation reason.
  pub reason: RevocationReason,
  /// Hash of all inputs.
  pub inputs_hash: InputsHash,
  /// Operator BLS signature.
  pub sig: BlsSig,
}

impl_payload!(ProUpRevTx);

impl BaseCodec for ProUpRevTx {
  fn decode(data: &mut &[u8]) -> Result<Self, DecodeError> {
    let version = u16::decode(data)?;
    Ok(Self {
      version,
      pro_tx_hash: TxHash::decode(data)?,
      reason: RevocationReason::decode(data)?,
      inputs_hash: InputsHash::decode(data)?,
      sig: BlsSig::decode(data, BlsScheme::from_protx_version(version))?,
    })
  }

  fn encode(&self, buf: &mut impl EncodeBuf) {
    self.version.encode(buf);
    self.pro_tx_hash.encode(buf);
    self.reason.encode(buf);
    self.inputs_hash.encode(buf);
    self.sig.encode(buf);
  }
}

impl Checkable for ProUpRevTx {
  type Error = ProTxInvalid;

  fn check(&self) -> Option<Self::Error> {
    if self.version == 0 {
      return Some(ProTxInvalid::BadVersion { version: self.version });
    }

    // A non-canonical signature counts as a payload decode failure.
    if !self.sig.is_canonical() {
      return Some(ProTxInvalid::BadPayload);
    }

    if matches!(self.reason, RevocationReason::Unknown(_)) {
      return Some(ProTxInvalid::BadReason { reason: self.reason });
    }

    None
  }
}

hash_impl!(ProUpRevTx);

/// Field set that tags the signature from the payload version.
#[cfg(feature = "serde")]
#[derive(::serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct __ProUpRevFields {
  version: u16,
  pro_tx_hash: TxHash,
  reason: RevocationReason,
  inputs_hash: InputsHash,
  #[serde(deserialize_with = "crate::serialize::bls::sig_bytes")]
  sig: [u8; BLS_SIG_LEN],
}

#[cfg(feature = "serde")]
impl From<__ProUpRevFields> for ProUpRevTx {
  fn from(fields: __ProUpRevFields) -> Self {
    Self {
      version: fields.version,
      pro_tx_hash: fields.pro_tx_hash,
      reason: fields.reason,
      inputs_hash: fields.inputs_hash,
      sig: BlsSig::from_bytes(fields.sig, BlsScheme::from_protx_version(fields.version)),
    }
  }
}

impl fmt::Display for ProUpRevTx {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "ProUpRevTx {{ v{} }}", self.version)
  }
}

#[cfg(all(test, feature = "serde"))]
#[expect(clippy::unwrap_used, reason = "test code")]
mod tests {
  use super::*;
  use crate::prelude::*;

  use dash_dev::{assert_serde_rt, check_sptx, from_json, to_json, Corpus};
  use rstest::rstest;

  #[rstest]
  fn corpus_prouprevtx() {
    let corpus = Corpus::open(env!("CARGO_MANIFEST_DIR"), "prouprevtx");
    let items = corpus.entries::<ProUpRevTx>("prouprevtx", check_sptx);
    assert_serde_rt("prouprevtx", &items);
  }

  /// Payload versions 1 and 2 share a layout, so a corpus payload serves for
  /// both once its version and tag change.
  #[rstest]
  #[case::legacy(1, BlsScheme::Legacy)]
  #[case::basic(2, BlsScheme::Basic)]
  fn sig_is_tagged_from_the_version(#[case] version: u16, #[case] scheme: BlsScheme) {
    let corpus = Corpus::open(env!("CARGO_MANIFEST_DIR"), "prouprevtx");
    let mut item = corpus
      .entries::<ProUpRevTx>("prouprevtx", |_, _, _| {})
      .into_values()
      .next()
      .unwrap();
    item.version = version;
    item.sig = BlsSig::from_bytes(*item.sig.as_bytes(), scheme);

    let mut buf = Vec::new();
    item.encode(&mut buf);
    let decoded = ProUpRevTx::decode(&mut buf.as_slice()).unwrap();
    assert_eq!(decoded.sig.scheme(), scheme);
    assert_eq!(decoded, item);
    assert_eq!(from_json::<ProUpRevTx>(&to_json(&item)), item);
  }

  #[rstest]
  fn non_canonical_signature_is_a_bad_payload() {
    let corpus = Corpus::open(env!("CARGO_MANIFEST_DIR"), "prouprevtx");
    let mut item = corpus
      .entries::<ProUpRevTx>("prouprevtx", |_, _, _| {})
      .into_values()
      .next()
      .unwrap();
    assert_eq!(item.check(), None);
    item.sig = item.sig.corrupted();
    assert_eq!(item.check(), Some(ProTxInvalid::BadPayload));
    assert_eq!(ProTxInvalid::BadPayload.to_string(), "bad-protx-payload");
  }
}
