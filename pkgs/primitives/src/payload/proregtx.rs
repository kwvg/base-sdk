//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! ProRegTx registration payload (type 1).

use super::{
  check_sptx_netinfo, InputsHash, MnType, ProTxInvalid, MAX_OPERATOR_REWARD, PROTX_VERSION_BASIC_BLS,
  PROTX_VERSION_EXT_ADDR,
};
use crate::codec::impl_payload;
use crate::prelude::*;
use crate::script::{KeyId, Script};
use crate::types::{NITrait, NetInfo, NetInfoV1, NetInfoV2, ServiceV1};
use crate::{hash_impl, TxHash};

use dash_pkc::bls::{BlsPkBytes, BlsScIetf};
use dash_types::codec::{BaseCodec, Checkable, DecodeError, EncodeBuf, NumCodec};
use dash_types::{make_bytes, TypeId};

use core::fmt;

/// ProRegTx -- register a new masternode (type 1).
///
/// - v1: LegacyBLS
/// - v2: BasicBLS
/// - v3: ExtAddr (extended network info)
#[derive(Clone, Debug, Eq, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
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
  /// Legacy ServiceV1 or extended NetInfo.
  pub net_info: NetInfo,
  /// Owner key id (20 bytes).
  pub key_id_owner: KeyId,
  /// Operator BLS public key (48 bytes).
  pub pub_key_operator: BlsPkBytes<BlsScIetf>,
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
  #[cfg_attr(feature = "serde", serde(rename = "platformP2PPort"))]
  pub platform_p2p_port: Option<u16>,
  /// Platform HTTP port (Evo + version < 3 only).
  #[cfg_attr(feature = "serde", serde(rename = "platformHTTPPort"))]
  pub platform_http_port: Option<u16>,
  /// Owner ECDSA signature (variable-length).
  #[cfg_attr(feature = "serde", serde(with = "dash_types::serialize::hex"))]
  pub vch_sig: Vec<u8>,
}

impl_payload!(ProRegTx);

/// Checks that platform fields are consistent with mn_type and version.
pub(super) fn check_platform_fields(
  mn_type: MnType,
  version: u16,
  platform_node_id: &Option<PlatformNodeId>,
  platform_p2p_port: Option<u16>,
  platform_http_port: Option<u16>,
) -> Option<ProTxInvalid> {
  if mn_type == MnType::Evo {
    if platform_node_id.is_none() {
      return Some(ProTxInvalid::BadPlatformFields);
    }
    if version < PROTX_VERSION_EXT_ADDR {
      if platform_p2p_port.is_none() || platform_http_port.is_none() {
        return Some(ProTxInvalid::BadPlatformFields);
      }
    } else if platform_p2p_port.is_some() || platform_http_port.is_some() {
      return Some(ProTxInvalid::BadPlatformFields);
    }
  } else if platform_node_id.is_some() || platform_p2p_port.is_some() || platform_http_port.is_some() {
    return Some(ProTxInvalid::BadPlatformFields);
  }
  None
}

impl BaseCodec for ProRegTx {
  fn decode(data: &mut &[u8]) -> Result<Self, DecodeError> {
    let version = u16::decode(data)?;
    let mn_type = MnType::from_base(u16::decode(data)?);
    let mode = u16::decode(data)?;
    let collateral_hash = TxHash::decode(data)?;
    let collateral_index = u32::decode(data)?;
    let net_info = if version >= 3 {
      NetInfo::Extended(NetInfoV2::decode(data)?)
    } else {
      NetInfo::Legacy(NetInfoV1(ServiceV1::decode(data)?))
    };
    let key_id_owner = KeyId::decode(data)?;
    let pub_key_operator = BlsPkBytes::<BlsScIetf>::decode(data)?;
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

  fn encode(&self, buf: &mut impl EncodeBuf) {
    self.version.encode(buf);
    self.mn_type.to_base().encode(buf);
    self.mode.encode(buf);
    self.collateral_hash.encode(buf);
    self.collateral_index.encode(buf);
    // Branch on version to match the decode path. Validation
    // guarantees the variant matches the version.
    if self.version >= 3 {
      if let NetInfo::Extended(ext) = &self.net_info {
        ext.encode(buf);
      }
    } else if let NetInfo::Legacy(svc) = &self.net_info {
      svc.encode(buf);
    }
    self.key_id_owner.encode(buf);
    self.pub_key_operator.encode(buf);
    self.key_id_voting.encode(buf);
    self.operator_reward.encode(buf);
    self.script_payout.encode(buf);
    self.inputs_hash.encode(buf);
    if self.mn_type == MnType::Evo {
      self.platform_node_id.unwrap_or_default().encode(buf);
      if self.version < 3 {
        self.platform_p2p_port.unwrap_or(0).encode(buf);
        self.platform_http_port.unwrap_or(0).encode(buf);
      }
    }
    self.vch_sig.encode(buf);
  }
}

impl Checkable for ProRegTx {
  type Error = ProTxInvalid;

  fn check(&self) -> Option<Self::Error> {
    if self.version == 0 {
      return Some(ProTxInvalid::BadVersion { version: self.version });
    }

    if self.mn_type == MnType::Evo && self.version < PROTX_VERSION_BASIC_BLS {
      return Some(ProTxInvalid::EvoVersionTooLow { version: self.version });
    }
    if matches!(self.mn_type, MnType::Unknown(_)) {
      return Some(ProTxInvalid::BadMnType { mn_type: self.mn_type });
    }
    if self.mode != 0 {
      return Some(ProTxInvalid::BadMode { mode: self.mode });
    }

    if self.key_id_owner.is_null() || self.key_id_voting.is_null() {
      return Some(ProTxInvalid::NullKey);
    }
    if self.pub_key_operator.is_null() {
      return Some(ProTxInvalid::NullKey);
    }

    let payout = self.script_payout.as_bytes();
    if !dash_script::is_p2pkh(payout) && !dash_script::is_p2sh(payout) {
      return Some(ProTxInvalid::BadPayoutScript);
    }

    let is_extended = matches!(self.net_info, NetInfo::Extended(_));
    if is_extended != (self.version >= PROTX_VERSION_EXT_ADDR) {
      return Some(ProTxInvalid::NetInfoVersionMismatch);
    }

    if !self.net_info.is_empty() {
      match &self.net_info {
        NetInfo::Legacy(addr) => {
          if let Some(error) = addr.check() {
            return Some(ProTxInvalid::NetInfoInvalid { error });
          }
        }
        NetInfo::Extended(addr) => {
          if let Some(e) = check_sptx_netinfo(addr, self.version, self.mn_type) {
            return Some(e);
          }
        }
      }
    }

    if let Some(e) = check_platform_fields(
      self.mn_type,
      self.version,
      &self.platform_node_id,
      self.platform_p2p_port,
      self.platform_http_port,
    ) {
      return Some(e);
    }

    if let Some(hash) = dash_script::p2pkh_hash160(payout) {
      if hash == self.key_id_owner.as_bytes() || hash == self.key_id_voting.as_bytes() {
        return Some(ProTxInvalid::PayoutKeyReuse);
      }
    }

    if self.operator_reward > MAX_OPERATOR_REWARD {
      return Some(ProTxInvalid::OperatorRewardTooHigh {
        reward: self.operator_reward,
      });
    }

    None
  }
}

hash_impl!(ProRegTx);

impl fmt::Display for ProRegTx {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "ProRegTx {{ v{}, mn_type: {} }}", self.version, self.mn_type)
  }
}

make_bytes! {
  /// Platform node identifier for Evo masternodes.
  PlatformNodeId, 20
}

hash_impl!(PlatformNodeId);

#[cfg(all(test, feature = "serde"))]
mod tests {
  use super::*;

  use dash_dev::{assert_serde_rt, check_sptx, load_corpus_file, read_corpus};
  use rstest::rstest;

  #[rstest]
  fn corpus_proregtx() {
    let text = load_corpus_file(env!("CARGO_MANIFEST_DIR"), "proregtx");
    let items = read_corpus::<ProRegTx>(&text, "proregtx", check_sptx);
    assert_serde_rt("proregtx", &items);
  }
}
