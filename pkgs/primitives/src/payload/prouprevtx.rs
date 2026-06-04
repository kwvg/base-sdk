//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! ProUpRevTx revocation payload (type 4).

use crate::error::DecodeError;
use crate::support::RevocationReason;
use crate::validation::{check_protx_version, max_protx_version_no_ext, DeploymentContext, ProTxInvalid};
use crate::wire;
use crate::{InputsHash, TxHash};

use bitcoin_consensus_encoding as encoding;
use dash_types::BlsSignatureBytes;

use core::fmt;

/// ProUpRevTx -- revoke a masternode (type 4).
///
/// - v1: LegacyBLS
/// - v2: BasicBLS
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
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

impl fmt::Display for ProUpRevTx {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "ProUpRevTx {{ v{} }}", self.version)
  }
}

impl ProUpRevTx {
  fn decode_for_codec(data: &[u8]) -> Result<Self, crate::codec::DecodeError> {
    Self::decode(data).map_err(Into::into)
  }

  /// Decodes from the extra_payload byte slice.
  pub fn decode(data: &[u8]) -> Result<Self, DecodeError> {
    let sl = &mut &data[..];

    let version = wire::read_u16_le(sl)?;
    let pro_tx_hash = wire::read_hash(sl)?.into();
    let reason_raw = wire::read_u16_le(sl)?;
    let reason = RevocationReason::from_u16(reason_raw);
    let inputs_hash = wire::read_hash(sl)?.into();
    let sig = wire::read_type(sl)?;

    Ok(Self {
      version,
      pro_tx_hash,
      reason,
      inputs_hash,
      sig,
    })
  }
}

impl encoding::Decodable for ProUpRevTx {
  type Decoder = crate::codec::BufferDecoder<Self, crate::codec::DecodeError>;
  fn decoder() -> Self::Decoder {
    crate::codec::BufferDecoder::new(Self::decode_for_codec, crate::MAX_EXTRA_PAYLOAD_SIZE)
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
