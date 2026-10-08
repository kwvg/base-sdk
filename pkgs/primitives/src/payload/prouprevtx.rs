//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! ProUpRevTx revocation payload (type 4).

use super::{InputsHash, ProTxInvalid};
use crate::codec::impl_payload;
use crate::support::RevocationReason;
use crate::{hash_impl, TxHash};

use dash_pkc::bls::{BlsScIetf, BlsSigBytes};
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
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
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
  pub sig: BlsSigBytes<BlsScIetf>,
}

impl_payload!(ProUpRevTx);

impl BaseCodec for ProUpRevTx {
  fn decode(data: &mut &[u8]) -> Result<Self, DecodeError> {
    Ok(Self {
      version: u16::decode(data)?,
      pro_tx_hash: TxHash::decode(data)?,
      reason: RevocationReason::decode(data)?,
      inputs_hash: InputsHash::decode(data)?,
      sig: BlsSigBytes::decode(data)?,
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

    if matches!(self.reason, RevocationReason::Unknown(_)) {
      return Some(ProTxInvalid::BadReason { reason: self.reason });
    }

    None
  }
}

hash_impl!(ProUpRevTx);

impl fmt::Display for ProUpRevTx {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "ProUpRevTx {{ v{} }}", self.version)
  }
}

#[cfg(all(test, feature = "serde"))]
mod tests {
  use super::*;

  use dash_dev::{assert_serde_rt, check_sptx, Corpus};
  use rstest::rstest;

  #[rstest]
  fn corpus_prouprevtx() {
    let corpus = Corpus::open(env!("CARGO_MANIFEST_DIR"), "prouprevtx");
    let items = corpus.entries::<ProUpRevTx>("prouprevtx", check_sptx);
    assert_serde_rt("prouprevtx", &items);
  }
}
