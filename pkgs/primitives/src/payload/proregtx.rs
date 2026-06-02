//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! ProRegTx registration payload (type 1).

use crate::error::DecodeError;
use crate::prelude::*;
use crate::script::Script;
use crate::support::CService;
use crate::tx_types::MnType;
use crate::validation::{
  check_net_info_trivially_valid, check_operator_key_not_null, check_protx_version, max_protx_version,
  DeploymentContext, ProTxInvalid, MAX_OPERATOR_REWARD, PROTX_VERSION_BASIC_BLS, PROTX_VERSION_EXT_ADDR,
};
use crate::wire;
use crate::{InputsHash, TxHash};

use bitcoin_consensus_encoding as encoding;
use dash_script::KeyId;
use dash_types::{BlsPublicKeyBytes, PlatformNodeId};

use core::fmt;

/// Maximum owner ECDSA signature size.
const MAX_VCH_SIG_SIZE: usize = 256;

/// Masternode network info: legacy CService or structured extended format.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum NetInfo {
  /// ADDRv1 CService (18 bytes).
  Legacy(CService),
  /// Extended format (v3+) with purpose-grouped entries.
  Extended(crate::support::ExtendedNetInfo),
}

/// ProRegTx -- register a new masternode (type 1).
///
/// - v1: LegacyBLS
/// - v2: BasicBLS
/// - v3: ExtAddr (extended network info)
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct ProRegTx {
  /// 1=LegacyBLS, 2=BasicBLS, 3=ExtAddr.
  pub version: u16,
  /// Masternode type (Regular or Evo).
  pub mn_type: MnType,
  /// Reserved, always 0.
  pub mode: u16,
  /// Collateral hash.
  pub collateral_hash: TxHash,
  /// Collateral index.
  pub collateral_index: u32,
  /// Legacy CService or extended NetInfo.
  pub net_info: NetInfo,
  /// Owner key id (20 bytes).
  pub key_id_owner: KeyId,
  /// Operator BLS public key (48 bytes).
  pub pub_key_operator: BlsPublicKeyBytes,
  /// Voting key id (20 bytes).
  pub key_id_voting: KeyId,
  /// Operator reward in basis points (0-10000).
  pub operator_reward: u16,
  /// Payout script.
  pub script_payout: Script,
  /// Hash of all inputs.
  pub inputs_hash: InputsHash,
  /// Platform node id (Evo only).
  pub platform_node_id: Option<PlatformNodeId>,
  /// Platform P2P port (Evo + version < 3 only).
  pub platform_p2p_port: Option<u16>,
  /// Platform HTTP port (Evo + version < 3 only).
  pub platform_http_port: Option<u16>,
  /// Owner ECDSA signature (variable-length).
  pub vch_sig: Vec<u8>,
}

impl fmt::Display for ProRegTx {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "ProRegTx {{ v{}, mn_type: {} }}", self.version, self.mn_type)
  }
}

impl ProRegTx {
  fn decode_for_codec(data: &[u8]) -> Result<Self, crate::codec::DecodeError> {
    Self::decode(data).map_err(Into::into)
  }

  /// Decodes from the extra_payload byte slice.
  pub fn decode(data: &[u8]) -> Result<Self, DecodeError> {
    let sl = &mut &data[..];

    let version = wire::read_u16_le(sl)?;
    let mn_type_raw = wire::read_u16_le(sl)?;
    let mn_type = MnType::from_u16(mn_type_raw);
    let mode = wire::read_u16_le(sl)?;
    let collateral_hash = wire::read_hash(sl)?.into();
    let collateral_index = wire::read_u32_le(sl)?;

    let net_info = if version >= 3 {
      let raw = wire::read_vec(sl, 1024)?;
      NetInfo::Extended(crate::support::ExtendedNetInfo::decode(&raw)?)
    } else {
      NetInfo::Legacy(wire::read_cservice(sl)?)
    };

    let key_id_owner = wire::read_type(sl)?;
    let pub_key_operator = wire::read_type(sl)?;
    let key_id_voting = wire::read_type(sl)?;
    let operator_reward = wire::read_u16_le(sl)?;
    let script_payout = wire::read_script(sl, 10_000)?;
    let inputs_hash = wire::read_hash(sl)?.into();

    let (platform_node_id, platform_p2p_port, platform_http_port) = if mn_type == MnType::Evo {
      let node_id = wire::read_type(sl)?;
      if version < 3 {
        let p2p = wire::read_u16_le(sl)?;
        let http = wire::read_u16_le(sl)?;
        (Some(node_id), Some(p2p), Some(http))
      } else {
        (Some(node_id), None, None)
      }
    } else {
      (None, None, None)
    };

    let vch_sig = wire::read_vec(sl, MAX_VCH_SIG_SIZE)?;

    Ok(Self {
      version,
      mn_type,
      mode,
      collateral_hash,
      collateral_index,
      net_info,
      key_id_owner,
      pub_key_operator,
      key_id_voting,
      operator_reward,
      script_payout,
      inputs_hash,
      platform_node_id,
      platform_p2p_port,
      platform_http_port,
      vch_sig,
    })
  }
}

impl encoding::Decodable for ProRegTx {
  type Decoder = crate::codec::BufferDecoder<Self, crate::codec::DecodeError>;
  fn decoder() -> Self::Decoder {
    crate::codec::BufferDecoder::new(Self::decode_for_codec, crate::MAX_EXTRA_PAYLOAD_SIZE)
  }
}

impl ProRegTx {
  /// Validates structural invariants without chain context.
  ///
  /// # Errors
  ///
  /// Returns the first validation error encountered.
  pub fn validate(&self, ctx: &DeploymentContext) -> Result<(), ProTxInvalid> {
    check_protx_version(self.version, max_protx_version(ctx))?;

    if self.mn_type == MnType::Evo && self.version < PROTX_VERSION_BASIC_BLS {
      return Err(ProTxInvalid::EvoVersionTooLow { version: self.version });
    }
    if matches!(self.mn_type, MnType::Unknown(_)) {
      return Err(ProTxInvalid::BadMnType { mn_type: self.mn_type });
    }
    if self.mode != 0 {
      return Err(ProTxInvalid::BadMode { mode: self.mode });
    }

    if self.key_id_owner.is_null() || self.key_id_voting.is_null() {
      return Err(ProTxInvalid::NullKey);
    }
    check_operator_key_not_null(&self.pub_key_operator)?;

    let payout = self.script_payout.as_bytes();
    if !dash_script::is_p2pkh(payout) && !dash_script::is_p2sh(payout) {
      return Err(ProTxInvalid::BadPayoutScript);
    }

    let is_extended = matches!(self.net_info, NetInfo::Extended(_));
    if is_extended != (self.version == PROTX_VERSION_EXT_ADDR) {
      return Err(ProTxInvalid::NetInfoVersionMismatch);
    }

    if let NetInfo::Extended(ref ext) = self.net_info {
      if ext.entries.is_empty() {
        return Err(ProTxInvalid::NetInfoEmpty);
      }
      check_net_info_trivially_valid(&ext.entries, self.mn_type, self.version == PROTX_VERSION_EXT_ADDR)?;
    }

    if let Some(hash) = dash_script::p2pkh_hash160(payout) {
      if hash == self.key_id_owner.as_bytes() || hash == self.key_id_voting.as_bytes() {
        return Err(ProTxInvalid::PayoutKeyReuse);
      }
    }

    if self.operator_reward > MAX_OPERATOR_REWARD {
      return Err(ProTxInvalid::OperatorRewardTooHigh {
        reward: self.operator_reward,
      });
    }

    Ok(())
  }
}
