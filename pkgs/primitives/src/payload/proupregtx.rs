//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! ProUpRegTx registrar-update payload (type 3).

use crate::error::DecodeError;
use crate::prelude::*;
use crate::script::Script;
use crate::validation::{
  check_operator_key_not_null, check_protx_version, max_protx_version_no_ext, DeploymentContext, ProTxInvalid,
};
use crate::wire;
use crate::{InputsHash, TxHash};

use bitcoin_consensus_encoding as encoding;
use dash_script::KeyId;
use dash_types::BlsPublicKeyBytes;

use core::fmt;

/// Maximum owner ECDSA signature size.
const MAX_VCH_SIG_SIZE: usize = 256;

/// ProUpRegTx -- update MN keys/payout (type 3).
///
/// - v1: LegacyBLS
/// - v2: BasicBLS
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct ProUpRegTx {
  /// 1=LegacyBLS, 2=BasicBLS.
  pub version: u16,
  /// ProTx hash identifying the masternode.
  pub pro_tx_hash: TxHash,
  /// Reserved, always 0.
  pub mode: u16,
  /// Operator BLS public key (48 bytes).
  pub pub_key_operator: BlsPublicKeyBytes,
  /// Voting key id (20 bytes).
  pub key_id_voting: KeyId,
  /// Payout script.
  pub script_payout: Script,
  /// Hash of all inputs.
  pub inputs_hash: InputsHash,
  /// Owner ECDSA signature (variable-length).
  pub vch_sig: Vec<u8>,
}

impl fmt::Display for ProUpRegTx {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "ProUpRegTx {{ v{} }}", self.version)
  }
}

impl ProUpRegTx {
  fn decode_for_codec(data: &[u8]) -> Result<Self, crate::codec::DecodeError> {
    Self::decode(data).map_err(Into::into)
  }

  /// Decodes from the extra_payload byte slice.
  pub fn decode(data: &[u8]) -> Result<Self, DecodeError> {
    let sl = &mut &data[..];

    let version = wire::read_u16_le(sl)?;
    let pro_tx_hash = wire::read_hash(sl)?.into();
    let mode = wire::read_u16_le(sl)?;
    let pub_key_operator = wire::read_type(sl)?;
    let key_id_voting = wire::read_type(sl)?;
    let script_payout = wire::read_script(sl, 10_000)?;
    let inputs_hash = wire::read_hash(sl)?.into();
    let vch_sig = wire::read_vec(sl, MAX_VCH_SIG_SIZE)?;

    Ok(Self {
      version,
      pro_tx_hash,
      mode,
      pub_key_operator,
      key_id_voting,
      script_payout,
      inputs_hash,
      vch_sig,
    })
  }
}

impl encoding::Decodable for ProUpRegTx {
  type Decoder = crate::codec::BufferDecoder<Self, crate::codec::DecodeError>;
  fn decoder() -> Self::Decoder {
    crate::codec::BufferDecoder::new(Self::decode_for_codec, crate::MAX_EXTRA_PAYLOAD_SIZE)
  }
}

impl ProUpRegTx {
  /// Validates structural invariants without chain context.
  ///
  /// # Errors
  ///
  /// Returns the first validation error encountered.
  pub fn validate(&self, ctx: &DeploymentContext) -> Result<(), ProTxInvalid> {
    check_protx_version(self.version, max_protx_version_no_ext(ctx))?;

    if self.mode != 0 {
      return Err(ProTxInvalid::BadMode { mode: self.mode });
    }

    check_operator_key_not_null(&self.pub_key_operator)?;
    if self.key_id_voting.is_null() {
      return Err(ProTxInvalid::NullKey);
    }

    let payout = self.script_payout.as_bytes();
    if !dash_script::is_p2pkh(payout) && !dash_script::is_p2sh(payout) {
      return Err(ProTxInvalid::BadPayoutScript);
    }

    Ok(())
  }
}
