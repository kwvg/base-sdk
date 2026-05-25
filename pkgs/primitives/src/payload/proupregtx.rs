//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! ProUpRegTx registrar-update payload (type 3).

use crate::prelude::*;
use crate::script::Script;
use crate::validation::{
  check_operator_key_not_null, check_protx_version, max_protx_version_no_ext, DeploymentContext, ProTxInvalid,
};
use crate::{InputsHash, TxHash};

use bitcoin_consensus_encoding as encoding;
use dash_script::KeyId;
use dash_types::codec::{self, Codec, DecodeError};
use dash_types::BlsPublicKeyBytes;

use core::fmt;

/// Maximum owner ECDSA signature size.
const MAX_VCH_SIG_SIZE: usize = 256;

/// ProUpRegTx -- update MN keys/payout (type 3).
///
/// - v1: LegacyBLS
/// - v2: BasicBLS
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
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
  #[cfg_attr(feature = "serde", serde(with = "dash_types::serialize::hex"))]
  pub vch_sig: Vec<u8>,
}

impl fmt::Display for ProUpRegTx {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "ProUpRegTx {{ v{} }}", self.version)
  }
}

impl ProUpRegTx {
  /// Decodes from the extra_payload byte slice.
  pub fn decode(data: &mut &[u8]) -> Result<Self, DecodeError> {
    let version = codec::read_u16_le(data)?;
    let pro_tx_hash = TxHash::decode(data)?;
    let mode = codec::read_u16_le(data)?;
    let pub_key_operator = codec::read_type(data)?;
    let key_id_voting = codec::read_type(data)?;
    let script_payout = Script::decode(data)?;
    let inputs_hash = InputsHash::decode(data)?;
    let vch_sig = codec::read_blob(data, MAX_VCH_SIG_SIZE)?;

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
  type Decoder = dash_types::BufferDecoder<Self, DecodeError>;
  fn decoder() -> Self::Decoder {
    dash_types::BufferDecoder::new(Self::decode, crate::MAX_EXTRA_PAYLOAD_SIZE)
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
