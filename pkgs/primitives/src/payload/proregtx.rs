//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! ProRegTx registration payload (type 1).

use crate::prelude::*;
use crate::script::Script;
use crate::support::CService;
use crate::tx_types::MnType;
use crate::validation::{
  check_net_info_trivially_valid, check_operator_key_not_null, check_protx_version, max_protx_version,
  DeploymentContext, ProTxInvalid, MAX_OPERATOR_REWARD, PROTX_VERSION_BASIC_BLS, PROTX_VERSION_EXT_ADDR,
};
use crate::{InputsHash, TxHash};

use dash_script::KeyId;
use dash_types::codec::{Codec, DecodeError, NumCodec};
use dash_types::{BlsPublicKeyBytes, PlatformNodeId};

use core::fmt;

/// Masternode network info: legacy CService or structured extended format.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
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
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
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
  #[cfg_attr(feature = "serde", serde(with = "dash_types::serialize::hex"))]
  pub vch_sig: Vec<u8>,
}

impl Codec for ProRegTx {
  fn decode(data: &mut &[u8]) -> Result<Self, DecodeError> {
    let version = u16::decode(data)?;
    let mn_type = MnType::from_base(u16::decode(data)?);
    let mode = u16::decode(data)?;
    let collateral_hash = TxHash::decode(data)?;
    let collateral_index = u32::decode(data)?;
    let net_info = if version >= 3 {
      let raw: Vec<u8> = Vec::decode(data)?;
      NetInfo::Extended(crate::support::ExtendedNetInfo::decode(&mut &raw[..])?)
    } else {
      NetInfo::Legacy(CService::decode(data)?)
    };
    let key_id_owner = KeyId::decode(data)?;
    let pub_key_operator = BlsPublicKeyBytes::decode(data)?;
    let key_id_voting = KeyId::decode(data)?;
    let operator_reward = u16::decode(data)?;
    let script_payout = Script::decode(data)?;
    let inputs_hash = InputsHash::decode(data)?;
    let (platform_node_id, platform_p2p_port, platform_http_port) = if mn_type == MnType::Evo {
      let node_id = PlatformNodeId::decode(data)?;
      if version < 3 {
        (Some(node_id), Some(u16::decode(data)?), Some(u16::decode(data)?))
      } else {
        (Some(node_id), None, None)
      }
    } else {
      (None, None, None)
    };

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
      vch_sig: Vec::decode(data)?,
    })
  }

  fn encode(&self, buf: &mut Vec<u8>) {
    self.version.encode(buf);
    self.mn_type.to_base().encode(buf);
    self.mode.encode(buf);
    self.collateral_hash.encode(buf);
    self.collateral_index.encode(buf);
    match &self.net_info {
      NetInfo::Extended(ext) => {
        let mut inner = Vec::new();
        ext.encode(&mut inner);
        inner.encode(buf);
      }
      NetInfo::Legacy(svc) => svc.encode(buf),
    }
    self.key_id_owner.encode(buf);
    self.pub_key_operator.encode(buf);
    self.key_id_voting.encode(buf);
    self.operator_reward.encode(buf);
    self.script_payout.encode(buf);
    self.inputs_hash.encode(buf);
    if self.mn_type == MnType::Evo {
      if let Some(ref node_id) = self.platform_node_id {
        node_id.encode(buf);
      }
      if self.version < 3 {
        self.platform_p2p_port.unwrap_or(0).encode(buf);
        self.platform_http_port.unwrap_or(0).encode(buf);
      }
    }
    self.vch_sig.encode(buf);
  }
}

crate::codec::impl_payload!(ProRegTx);

impl fmt::Display for ProRegTx {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "ProRegTx {{ v{}, mn_type: {} }}", self.version, self.mn_type)
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
