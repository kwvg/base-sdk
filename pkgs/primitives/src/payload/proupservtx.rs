//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! ProUpServTx service-update payload (type 2).

use super::proregtx::check_platform_fields;
use super::{check_sptx_netinfo, InputsHash, MnType, ProTxInvalid, PROTX_VERSION_BASIC_BLS, PROTX_VERSION_EXT_ADDR};
use crate::codec::impl_payload;
use crate::payload::PlatformNodeId;
use crate::types::{BlsScheme, BlsSig, NITrait, NetInfo, NetInfoV1, NetInfoV2, ServiceV1};
use crate::{hash_impl, TxHash};

use bitcoin_primitives::script::ScriptPubKeyBuf;
#[cfg(feature = "serde")]
use dash_pkc::bls::BLS_SIG_LEN;
use dash_types::codec::{BaseCodec, DecodeError, EncodeBuf};
use dash_types::{type_id::TypeId, Checkable, Numeric};

use core::fmt;

/// ProUpServTx -- update MN service addr (type 2).
///
/// - v1: LegacyBLS (no mn_type field)
/// - v2: BasicBLS (adds mn_type)
/// - v3: ExtAddr (extended network info)
#[derive(Clone, Debug, Eq, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase", from = "__ProUpServFields"))]
pub struct ProUpServTx {
  /// 1=LegacyBLS, 2=BasicBLS, 3=ExtAddr.
  pub version: u16,
  /// v2+ only; defaults to Regular for v1.
  pub mn_type: MnType,
  /// ProTx hash identifying the masternode.
  pub pro_tx_hash: TxHash,
  /// Legacy ServiceV1 or extended NetInfo.
  pub net_info: NetInfo,
  /// Operator payout script.
  pub script_operator_payout: ScriptPubKeyBuf,
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
  /// Operator BLS signature.
  pub sig: BlsSig,
}

impl_payload!(ProUpServTx);

impl BaseCodec for ProUpServTx {
  fn decode(data: &mut &[u8]) -> Result<Self, DecodeError> {
    let version = u16::decode(data)?;

    let mn_type = if version >= 2 {
      MnType::from_base(u16::decode(data)?)
    } else {
      MnType::Regular
    };

    let pro_tx_hash = TxHash::decode(data)?;
    let net_info = if version >= 3 {
      NetInfo::Extended(NetInfoV2::decode(data)?)
    } else {
      NetInfo::Legacy(NetInfoV1(ServiceV1::decode(data)?))
    };
    let script_operator_payout = ScriptPubKeyBuf::decode(data)?;
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
      pro_tx_hash,
      net_info,
      script_operator_payout,
      inputs_hash,
      platform_node_id,
      platform_p2p_port,
      platform_http_port,
      sig: BlsSig::decode(data, BlsScheme::from_protx_version(version))?,
    })
  }

  fn encode(&self, buf: &mut impl EncodeBuf) {
    self.version.encode(buf);
    if self.version >= 2 {
      self.mn_type.to_base().encode(buf);
    }
    self.pro_tx_hash.encode(buf);
    // Branch on version to match the decode path. Validation
    // guarantees the variant matches the version.
    if self.version >= 3 {
      if let NetInfo::Extended(ext) = &self.net_info {
        ext.encode(buf);
      }
    } else if let NetInfo::Legacy(svc) = &self.net_info {
      svc.encode(buf);
    }
    self.script_operator_payout.encode(buf);
    self.inputs_hash.encode(buf);
    if self.mn_type == MnType::Evo {
      self.platform_node_id.unwrap_or_default().encode(buf);
      if self.version < 3 {
        self.platform_p2p_port.unwrap_or(0).encode(buf);
        self.platform_http_port.unwrap_or(0).encode(buf);
      }
    }
    self.sig.encode(buf);
  }
}

impl Checkable for ProUpServTx {
  type Error = ProTxInvalid;

  fn check(&self) -> Option<Self::Error> {
    if self.version == 0 || self.version > PROTX_VERSION_EXT_ADDR {
      return Some(ProTxInvalid::BadVersion { version: self.version });
    }

    // A non-canonical signature counts as a payload decode failure.
    if !self.sig.is_canonical() {
      return Some(ProTxInvalid::BadPayload);
    }

    if matches!(self.mn_type, MnType::Unknown(_)) {
      return Some(ProTxInvalid::BadMnType { mn_type: self.mn_type });
    }

    if self.mn_type == MnType::Evo && self.version < PROTX_VERSION_BASIC_BLS {
      return Some(ProTxInvalid::EvoVersionTooLow { version: self.version });
    }

    let is_extended = matches!(self.net_info, NetInfo::Extended(_));
    if is_extended != (self.version >= PROTX_VERSION_EXT_ADDR) {
      return Some(ProTxInvalid::NetInfoVersionMismatch);
    }

    match &self.net_info {
      NetInfo::Legacy(addr) => {
        if addr.is_empty() {
          return Some(ProTxInvalid::NetInfoEmpty);
        }
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

    if let Some(e) = check_platform_fields(
      self.mn_type,
      self.version,
      &self.platform_node_id,
      self.platform_p2p_port,
      self.platform_http_port,
    ) {
      return Some(e);
    }

    None
  }
}

hash_impl!(ProUpServTx);

/// Field set that tags the signature from the payload version.
#[cfg(feature = "serde")]
#[derive(::serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct __ProUpServFields {
  version: u16,
  mn_type: MnType,
  pro_tx_hash: TxHash,
  net_info: NetInfo,
  script_operator_payout: ScriptPubKeyBuf,
  inputs_hash: InputsHash,
  platform_node_id: Option<PlatformNodeId>,
  #[serde(rename = "platformP2PPort")]
  platform_p2p_port: Option<u16>,
  #[serde(rename = "platformHTTPPort")]
  platform_http_port: Option<u16>,
  #[serde(deserialize_with = "crate::serialize::bls::sig_bytes")]
  sig: [u8; BLS_SIG_LEN],
}

#[cfg(feature = "serde")]
impl From<__ProUpServFields> for ProUpServTx {
  fn from(fields: __ProUpServFields) -> Self {
    Self {
      version: fields.version,
      mn_type: fields.mn_type,
      pro_tx_hash: fields.pro_tx_hash,
      net_info: fields.net_info,
      script_operator_payout: fields.script_operator_payout,
      inputs_hash: fields.inputs_hash,
      platform_node_id: fields.platform_node_id,
      platform_p2p_port: fields.platform_p2p_port,
      platform_http_port: fields.platform_http_port,
      sig: BlsSig::from_bytes(fields.sig, BlsScheme::from_protx_version(fields.version)),
    }
  }
}

impl fmt::Display for ProUpServTx {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "ProUpServTx {{ v{}, mn_type: {} }}", self.version, self.mn_type,)
  }
}

#[cfg(all(test, feature = "serde"))]
mod tests {
  use super::*;
  use crate::prelude::*;

  use dash_dev::{assert_serde_rt, check_sptx, Corpus};
  use rstest::rstest;

  fn corpus_item(version: u16, mn_type: MnType) -> ProUpServTx {
    let corpus = Corpus::open(env!("CARGO_MANIFEST_DIR"), "proupservtx");
    let items: Vec<ProUpServTx> = corpus
      .entries::<ProUpServTx>("proupservtx", |_, _, _| {})
      .into_values()
      .filter(|item| item.version == version && item.mn_type == mn_type)
      .collect();
    assert!(!items.is_empty(), "no v{version} {mn_type} payload in the corpus");
    items[0].clone()
  }

  #[rstest]
  fn corpus_proupservtx() {
    let corpus = Corpus::open(env!("CARGO_MANIFEST_DIR"), "proupservtx");
    let items = corpus.entries::<ProUpServTx>("proupservtx", check_sptx);
    assert_serde_rt("proupservtx", &items);
  }

  #[rstest]
  #[case::zero(0)]
  #[case::past_ext_addr(4)]
  #[case::max(u16::MAX)]
  fn version_outside_one_to_three_is_rejected(#[case] version: u16) {
    let mut item = corpus_item(2, MnType::Regular);
    item.version = version;
    assert_eq!(item.check(), Some(ProTxInvalid::BadVersion { version }));
  }

  #[rstest]
  fn sig_is_tagged_from_the_version() {
    let corpus = Corpus::open(env!("CARGO_MANIFEST_DIR"), "proupservtx");
    let items = corpus.entries::<ProUpServTx>("proupservtx", |_, _, _| {});
    let mut seen = BTreeSet::new();
    for (label, item) in &items {
      let scheme = item.sig.scheme();
      let expected = if item.version == 1 {
        BlsScheme::Legacy
      } else {
        BlsScheme::Basic
      };
      assert_eq!(scheme, expected, "{label}");
      seen.insert(item.version.min(2));
    }
    assert_eq!(seen.len(), 2, "the corpus covers both schemes");
  }

  /// Corpus payloads of both schemes reject a corrupted signature.
  #[rstest]
  fn non_canonical_signature_is_a_bad_payload() {
    let corpus = Corpus::open(env!("CARGO_MANIFEST_DIR"), "proupservtx");
    let mut seen = BTreeSet::new();
    for (label, mut item) in corpus.entries::<ProUpServTx>("proupservtx", |_, _, _| {}) {
      assert_eq!(item.check(), None, "{label}");
      seen.insert(item.version.min(2));
      item.sig = item.sig.corrupted();
      assert_eq!(item.check(), Some(ProTxInvalid::BadPayload), "{label}");
    }
    assert_eq!(seen.len(), 2);
  }
}
