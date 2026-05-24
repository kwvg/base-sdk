//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! ProUpServTx service-update payload (type 2).

use super::proregtx::NetInfo;
use crate::script::Script;
use crate::tx_types::MnType;
use crate::validation::{
  check_net_info_trivially_valid, check_protx_version, max_protx_version, DeploymentContext, ProTxInvalid,
  PROTX_VERSION_BASIC_BLS, PROTX_VERSION_EXT_ADDR,
};
use crate::wire;
use crate::{InputsHash, TxHash};

use bitcoin_consensus_encoding as encoding;
use dash_types::codec::{self, DecodeError, NumCodec};
use dash_types::{BlsSignatureBytes, PlatformNodeId};

use core::fmt;

/// ProUpServTx -- update MN service addr (type 2).
///
/// - v1: LegacyBLS (no mn_type field)
/// - v2: BasicBLS (adds mn_type)
/// - v3: ExtAddr (extended network info)
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct ProUpServTx {
  /// 1=LegacyBLS, 2=BasicBLS, 3=ExtAddr.
  pub version: u16,
  /// v2+ only; defaults to Regular for v1.
  pub mn_type: MnType,
  /// ProTx hash identifying the masternode.
  pub pro_tx_hash: TxHash,
  /// Legacy CService or extended NetInfo.
  pub net_info: NetInfo,
  /// Operator payout script.
  pub script_operator_payout: Script,
  /// Hash of all inputs.
  pub inputs_hash: InputsHash,
  /// Platform node id (Evo only).
  pub platform_node_id: Option<PlatformNodeId>,
  /// Platform P2P port (Evo + version < 3 only).
  pub platform_p2p_port: Option<u16>,
  /// Platform HTTP port (Evo + version < 3 only).
  pub platform_http_port: Option<u16>,
  /// Operator BLS signature.
  pub sig: BlsSignatureBytes,
}

impl fmt::Display for ProUpServTx {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "ProUpServTx {{ v{}, mn_type: {} }}", self.version, self.mn_type,)
  }
}

impl ProUpServTx {
  /// Decodes from the extra_payload byte slice.
  pub fn decode(data: &mut &[u8]) -> Result<Self, DecodeError> {
    let version = codec::read_u16_le(data)?;

    let mn_type = if version >= 2 {
      let raw = codec::read_u16_le(data)?;
      MnType::from_base(raw)
    } else {
      MnType::Regular
    };

    let pro_tx_hash = wire::read_hash(data)?.into();

    let net_info = if version >= 3 {
      let raw = wire::read_vec(data, 1024)?;
      NetInfo::Extended(crate::support::ExtendedNetInfo::decode(&mut &raw[..])?)
    } else {
      NetInfo::Legacy(wire::read_cservice(data)?)
    };

    let script_operator_payout = wire::read_script(data, 10_000)?;
    let inputs_hash = wire::read_hash(data)?.into();

    let (platform_node_id, platform_p2p_port, platform_http_port) = if mn_type == MnType::Evo {
      let node_id = codec::read_type(data)?;
      if version < 3 {
        let p2p = codec::read_u16_le(data)?;
        let http = codec::read_u16_le(data)?;
        (Some(node_id), Some(p2p), Some(http))
      } else {
        (Some(node_id), None, None)
      }
    } else {
      (None, None, None)
    };

    let sig = codec::read_type(data)?;

    Ok(Self {
      version,
      mn_type,
      pro_tx_hash,
      net_info,
      script_operator_payout,
      inputs_hash,
      platform_node_id,
      platform_p2p_port,
      platform_http_port,
      sig,
    })
  }
}

impl encoding::Decodable for ProUpServTx {
  type Decoder = crate::codec::BufferDecoder<Self, DecodeError>;
  fn decoder() -> Self::Decoder {
    crate::codec::BufferDecoder::new(Self::decode, crate::MAX_EXTRA_PAYLOAD_SIZE)
  }
}

impl ProUpServTx {
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

    let is_extended = matches!(self.net_info, NetInfo::Extended(_));
    if is_extended != (self.version == PROTX_VERSION_EXT_ADDR) {
      return Err(ProTxInvalid::NetInfoVersionMismatch);
    }

    match &self.net_info {
      NetInfo::Extended(ext) => {
        if ext.entries.is_empty() {
          return Err(ProTxInvalid::NetInfoEmpty);
        }
        check_net_info_trivially_valid(&ext.entries, self.mn_type, self.version == PROTX_VERSION_EXT_ADDR)?;
      }
      NetInfo::Legacy(svc) => {
        if svc.addr == [0u8; 16] && svc.port == 0 {
          return Err(ProTxInvalid::NetInfoEmpty);
        }
      }
    }

    Ok(())
  }
}
