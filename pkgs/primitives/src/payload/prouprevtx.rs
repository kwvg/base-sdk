//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! ProUpRevTx revocation payload (type 4).

use crate::prelude::*;
use crate::support::RevocationReason;
use crate::validation::{check_protx_version, max_protx_version_no_ext, DeploymentContext, ProTxInvalid};
use crate::{InputsHash, TxHash};

use dash_types::codec::{Codec, DecodeError, NumCodec};
use dash_types::BlsSignatureBytes;

use core::fmt;

/// ProUpRevTx -- revoke a masternode (type 4).
///
/// - v1: LegacyBLS
/// - v2: BasicBLS
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
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
  pub sig: BlsSignatureBytes,
}

impl Codec for ProUpRevTx {
  fn decode(data: &mut &[u8]) -> Result<Self, DecodeError> {
    Ok(Self {
      version: u16::decode(data)?,
      pro_tx_hash: TxHash::decode(data)?,
      reason: RevocationReason::from_base(u16::decode(data)?),
      inputs_hash: InputsHash::decode(data)?,
      sig: BlsSignatureBytes::decode(data)?,
    })
  }

  fn encode(&self, buf: &mut Vec<u8>) {
    self.version.encode(buf);
    self.pro_tx_hash.encode(buf);
    self.reason.to_base().encode(buf);
    self.inputs_hash.encode(buf);
    self.sig.encode(buf);
  }
}

crate::codec::impl_payload!(ProUpRevTx);

impl fmt::Display for ProUpRevTx {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "ProUpRevTx {{ v{} }}", self.version)
  }
}

impl ProUpRevTx {
  /// Validates structural invariants without chain context.
  ///
  /// # Errors
  ///
  /// Returns the first validation error encountered.
  pub fn validate(&self, ctx: &DeploymentContext) -> Result<(), ProTxInvalid> {
    check_protx_version(self.version, max_protx_version_no_ext(ctx))?;

    if matches!(self.reason, RevocationReason::Unknown(_)) {
      return Err(ProTxInvalid::BadReason { reason: self.reason });
    }

    Ok(())
  }
}
