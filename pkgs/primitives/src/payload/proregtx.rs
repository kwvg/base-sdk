//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! ProRegTx registration payload (type 1).

use super::{
  check_sptx_netinfo, decode_version, InputsHash, MnType, ProTxInvalid, MAX_OPERATOR_REWARD, PROTX_VERSION_BASIC_BLS,
  PROTX_VERSION_EXT_ADDR,
};
use crate::codec::impl_payload;
use crate::payload::PlatformNodeId;
use crate::prelude::*;
use crate::types::{BlsPubKey, BlsScheme, NITrait, NetInfo, NetInfoV1, NetInfoV2, ServiceV1};
use crate::{hash_impl, TxHash};

use bitcoin_primitives::script::ScriptPubKeyBuf;
use dash_pkc::bls::BLS_PK_LEN;
use dash_script::{PubKeyHash, Recipient};
use dash_types::codec::{BaseCodec, DecodeError, EncodeBuf};
use dash_types::type_id::TypeId;
use dash_types::{Checkable, Numeric};

use core::fmt;

/// ProRegTx -- register a new masternode (type 1).
///
/// - v1: LegacyBLS
/// - v2: BasicBLS
/// - v3: ExtAddr (extended network info)
///
/// The version-coupled fields are private, so [`ProRegTx::new`] keeps them in
/// step with the version and masternode type.
#[derive(Clone, Debug, Eq, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase", try_from = "__ProRegFields"))]
pub struct ProRegTx {
  version: u16,
  mn_type: MnType,
  /// Reserved, always 0.
  pub mode: u16,
  /// Collateral hash.
  pub collateral_hash: TxHash,
  /// Collateral index.
  pub collateral_index: u32,
  net_info: NetInfo,
  /// Owner key id (20 bytes).
  pub key_id_owner: PubKeyHash,
  pub_key_operator: BlsPubKey,
  /// Voting key id (20 bytes).
  pub key_id_voting: PubKeyHash,
  /// Operator reward in basis points (0-10000).
  pub operator_reward: u16,
  /// Payout script.
  pub script_payout: ScriptPubKeyBuf,
  /// Hash of all inputs.
  pub inputs_hash: InputsHash,
  platform_node_id: Option<PlatformNodeId>,
  #[cfg_attr(feature = "serde", serde(rename = "platformP2PPort"))]
  platform_p2p_port: Option<u16>,
  #[cfg_attr(feature = "serde", serde(rename = "platformHTTPPort"))]
  platform_http_port: Option<u16>,
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
    let version = decode_version(data)?;
    let mn_type = MnType::from_base(u16::decode(data)?);
    let mode = u16::decode(data)?;
    let collateral_hash = TxHash::decode(data)?;
    let collateral_index = u32::decode(data)?;
    let net_info = if version >= 3 {
      NetInfo::Extended(NetInfoV2::decode(data)?)
    } else {
      NetInfo::Legacy(NetInfoV1(ServiceV1::decode(data)?))
    };
    let key_id_owner = PubKeyHash::decode(data)?;
    let pub_key_operator = BlsPubKey::decode(data, BlsScheme::from_protx_version(version))?;
    let key_id_voting = PubKeyHash::decode(data)?;
    let operator_reward = u16::decode(data)?;
    let script_payout = ScriptPubKeyBuf::decode(data)?;
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
    match &self.net_info {
      NetInfo::Legacy(svc) => svc.encode(buf),
      NetInfo::Extended(ext) => ext.encode(buf),
    }
    self.key_id_owner.encode(buf);
    self.pub_key_operator.encode(buf);
    self.key_id_voting.encode(buf);
    self.operator_reward.encode(buf);
    self.script_payout.encode(buf);
    self.inputs_hash.encode(buf);
    if let Some(node_id) = self.platform_node_id {
      node_id.encode(buf);
    }
    if let Some(port) = self.platform_p2p_port {
      port.encode(buf);
    }
    if let Some(port) = self.platform_http_port {
      port.encode(buf);
    }
    self.vch_sig.encode(buf);
  }
}

impl Checkable for ProRegTx {
  type Error = ProTxInvalid;

  fn check(&self) -> Option<Self::Error> {
    if self.version == 0 || self.version > PROTX_VERSION_EXT_ADDR {
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
    // A non-canonical operator key is an invalid key, reported as null.
    if self.pub_key_operator.is_null() || !self.pub_key_operator.is_canonical() {
      return Some(ProTxInvalid::NullKey);
    }

    let payout = self.script_payout.as_bytes();
    let recipient = Recipient::from_script(payout);
    match &recipient {
      Some(Recipient::PubKeyHash(_) | Recipient::ScriptHash(_)) => {}
      _ => return Some(ProTxInvalid::BadPayoutScript),
    }

    if let Some(e) = self.check_fields() {
      return Some(e);
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

    if let Some(Recipient::PubKeyHash(hash)) = &recipient {
      if *hash == self.key_id_owner || *hash == self.key_id_voting {
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

impl ProRegTx {
  /// Builds a registration whose net info and platform fields match the
  /// version and masternode type. The version selects the scheme of
  /// `pub_key_operator`.
  ///
  /// # Errors
  ///
  /// Returns [`ProTxInvalid::NetInfoVersionMismatch`] or
  /// [`ProTxInvalid::BadPlatformFields`] for a field that does not match.
  #[expect(clippy::too_many_arguments, reason = "one argument per wire field")]
  pub fn new(
    version: u16,
    mn_type: MnType,
    mode: u16,
    collateral_hash: TxHash,
    collateral_index: u32,
    net_info: NetInfo,
    key_id_owner: PubKeyHash,
    pub_key_operator: [u8; BLS_PK_LEN],
    key_id_voting: PubKeyHash,
    operator_reward: u16,
    script_payout: ScriptPubKeyBuf,
    inputs_hash: InputsHash,
    platform_node_id: Option<PlatformNodeId>,
    platform_p2p_port: Option<u16>,
    platform_http_port: Option<u16>,
    vch_sig: Vec<u8>,
  ) -> Result<Self, ProTxInvalid> {
    let protx = Self {
      version,
      mn_type,
      mode,
      collateral_hash,
      collateral_index,
      net_info,
      key_id_owner,
      pub_key_operator: BlsPubKey::from_bytes(pub_key_operator, BlsScheme::from_protx_version(version)),
      key_id_voting,
      operator_reward,
      script_payout,
      inputs_hash,
      platform_node_id,
      platform_p2p_port,
      platform_http_port,
      vch_sig,
    };
    match protx.check_fields() {
      Some(error) => Err(error),
      None => Ok(protx),
    }
  }

  /// Payload version.
  pub const fn version(&self) -> u16 {
    self.version
  }

  /// Masternode type.
  pub const fn mn_type(&self) -> MnType {
    self.mn_type
  }

  /// Network addresses, legacy before version 3 and extended from it.
  pub const fn net_info(&self) -> &NetInfo {
    &self.net_info
  }

  /// Operator BLS public key, in the scheme the version selects.
  pub const fn pub_key_operator(&self) -> &BlsPubKey {
    &self.pub_key_operator
  }

  /// Platform node id, carried by evo masternodes.
  pub const fn platform_node_id(&self) -> Option<PlatformNodeId> {
    self.platform_node_id
  }

  /// Platform P2P port, carried by evo masternodes before version 3.
  pub const fn platform_p2p_port(&self) -> Option<u16> {
    self.platform_p2p_port
  }

  /// Platform HTTP port, carried by evo masternodes before version 3.
  pub const fn platform_http_port(&self) -> Option<u16> {
    self.platform_http_port
  }

  fn check_fields(&self) -> Option<ProTxInvalid> {
    let is_extended = matches!(self.net_info, NetInfo::Extended(_));
    if is_extended != (self.version >= PROTX_VERSION_EXT_ADDR) {
      return Some(ProTxInvalid::NetInfoVersionMismatch);
    }
    check_platform_fields(
      self.mn_type,
      self.version,
      &self.platform_node_id,
      self.platform_p2p_port,
      self.platform_http_port,
    )
  }
}

/// Field set that tags the operator key from the payload version and builds
/// the registration through [`ProRegTx::new`].
#[cfg(feature = "serde")]
#[derive(::serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct __ProRegFields {
  version: u16,
  mn_type: MnType,
  mode: u16,
  collateral_hash: TxHash,
  collateral_index: u32,
  net_info: NetInfo,
  key_id_owner: PubKeyHash,
  #[serde(deserialize_with = "crate::serialize::bls::pk_bytes")]
  pub_key_operator: [u8; BLS_PK_LEN],
  key_id_voting: PubKeyHash,
  operator_reward: u16,
  script_payout: ScriptPubKeyBuf,
  inputs_hash: InputsHash,
  platform_node_id: Option<PlatformNodeId>,
  #[serde(rename = "platformP2PPort")]
  platform_p2p_port: Option<u16>,
  #[serde(rename = "platformHTTPPort")]
  platform_http_port: Option<u16>,
  #[serde(with = "dash_types::serialize::hex")]
  vch_sig: Vec<u8>,
}

#[cfg(feature = "serde")]
impl TryFrom<__ProRegFields> for ProRegTx {
  type Error = ProTxInvalid;

  fn try_from(fields: __ProRegFields) -> Result<Self, Self::Error> {
    Self::new(
      fields.version,
      fields.mn_type,
      fields.mode,
      fields.collateral_hash,
      fields.collateral_index,
      fields.net_info,
      fields.key_id_owner,
      fields.pub_key_operator,
      fields.key_id_voting,
      fields.operator_reward,
      fields.script_payout,
      fields.inputs_hash,
      fields.platform_node_id,
      fields.platform_p2p_port,
      fields.platform_http_port,
      fields.vch_sig,
    )
  }
}

impl fmt::Display for ProRegTx {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "ProRegTx {{ v{}, mn_type: {} }}", self.version, self.mn_type)
  }
}

#[cfg(all(test, feature = "serde"))]
mod tests {
  use super::*;

  use dash_dev::{assert_serde_rt, check_sptx, from_json, json_rejects, to_json, Corpus};
  use hex_conservative::hex;
  use rstest::rstest;

  fn corpus_item(version: u16, mn_type: MnType) -> ProRegTx {
    let corpus = Corpus::open(env!("CARGO_MANIFEST_DIR"), "proregtx");
    let items: Vec<ProRegTx> = corpus
      .entries::<ProRegTx>("proregtx", |_, _, _| {})
      .into_values()
      .filter(|item| item.version == version && item.mn_type == mn_type)
      .collect();
    assert!(!items.is_empty(), "no v{version} {mn_type} payload in the corpus");
    items[0].clone()
  }

  #[rstest]
  fn corpus_proregtx() {
    let corpus = Corpus::open(env!("CARGO_MANIFEST_DIR"), "proregtx");
    let items = corpus.entries::<ProRegTx>("proregtx", check_sptx);
    assert_serde_rt("proregtx", &items);
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

  /// Payload versions 1 and 2 share a layout, so a version 2 corpus payload
  /// serves for both once its version and tag change.
  #[rstest]
  #[case::legacy(1, BlsScheme::Legacy)]
  #[case::basic(2, BlsScheme::Basic)]
  fn pub_key_operator_is_tagged_from_the_version(#[case] version: u16, #[case] scheme: BlsScheme) {
    let mut item = corpus_item(2, MnType::Regular);
    item.version = version;
    item.pub_key_operator = BlsPubKey::from_bytes(*item.pub_key_operator.as_bytes(), scheme);

    let mut buf = Vec::new();
    item.encode(&mut buf);
    assert_eq!(ProRegTx::decode(&mut buf.as_slice()), Ok(item.clone()));
    assert_eq!(item.pub_key_operator.scheme(), scheme);
    assert_eq!(from_json::<ProRegTx>(&to_json(&item)), item);
  }

  /// Rebuilds `item` through [`ProRegTx::new`] after `edit` changes it.
  fn rebuild(item: &ProRegTx, edit: impl FnOnce(&mut ProRegTx)) -> Result<ProRegTx, ProTxInvalid> {
    let mut t = item.clone();
    edit(&mut t);
    ProRegTx::new(
      t.version,
      t.mn_type,
      t.mode,
      t.collateral_hash,
      t.collateral_index,
      t.net_info,
      t.key_id_owner,
      *t.pub_key_operator.as_bytes(),
      t.key_id_voting,
      t.operator_reward,
      t.script_payout,
      t.inputs_hash,
      t.platform_node_id,
      t.platform_p2p_port,
      t.platform_http_port,
      t.vch_sig,
    )
  }

  #[rstest]
  #[case::regular_v2(2, MnType::Regular)]
  #[case::evo_v2(2, MnType::Evo)]
  #[case::evo_v3(3, MnType::Evo)]
  fn consistent_payloads_rebuild_unchanged(#[case] version: u16, #[case] mn_type: MnType) {
    let item = corpus_item(version, mn_type);
    assert_eq!(rebuild(&item, |_| {}), Ok(item.clone()));
    assert_eq!(
      (item.version(), item.mn_type(), item.net_info(), item.pub_key_operator()),
      (item.version, item.mn_type, &item.net_info, &item.pub_key_operator)
    );
    assert_eq!(
      (
        item.platform_node_id(),
        item.platform_p2p_port(),
        item.platform_http_port()
      ),
      (item.platform_node_id, item.platform_p2p_port, item.platform_http_port)
    );
  }

  /// An empty purpose group and an unknown version both reach the purpose
  /// checks, which find no core P2P entry.
  #[rstest]
  #[case::empty_group(&hex!("01010000"))]
  #[case::unknown_version(&hex!("00"))]
  fn non_empty_net_info_without_entries_is_checked(#[case] wire: &[u8]) {
    let item = corpus_item(3, MnType::Evo);
    let checked = NetInfoV2::decode(&mut &wire[..])
      .map(|v2| rebuild(&item, |t| t.net_info = NetInfo::Extended(v2)).map(|t| t.check()));
    assert_eq!(checked, Ok(Ok(Some(ProTxInvalid::NetInfoEmpty))));
  }

  #[rstest]
  fn net_info_must_match_the_version() {
    let v2 = corpus_item(2, MnType::Regular);
    let v3 = corpus_item(3, MnType::Evo);
    let extended = v3.net_info.clone();
    assert_eq!(
      rebuild(&v2, |t| t.net_info = extended),
      Err(ProTxInvalid::NetInfoVersionMismatch)
    );
    let legacy = v2.net_info.clone();
    assert_eq!(
      rebuild(&v3, |t| t.net_info = legacy),
      Err(ProTxInvalid::NetInfoVersionMismatch)
    );
  }

  #[rstest]
  #[case::legacy(1, BlsScheme::Legacy)]
  #[case::basic(2, BlsScheme::Basic)]
  fn operator_key_takes_the_scheme_of_the_version(#[case] version: u16, #[case] scheme: BlsScheme) {
    let v2 = corpus_item(2, MnType::Regular);
    let rebuilt = rebuild(&v2, |t| t.version = version);
    assert_eq!(rebuilt.map(|t| t.pub_key_operator().scheme()), Ok(scheme));
  }

  #[rstest]
  #[case::evo_v2_without_node_id(2, MnType::Evo, |t: &mut ProRegTx| t.platform_node_id = None)]
  #[case::evo_v2_without_p2p_port(2, MnType::Evo, |t: &mut ProRegTx| t.platform_p2p_port = None)]
  #[case::evo_v2_without_http_port(2, MnType::Evo, |t: &mut ProRegTx| t.platform_http_port = None)]
  #[case::evo_v3_with_ports(3, MnType::Evo, |t: &mut ProRegTx| t.platform_p2p_port = Some(1))]
  #[case::regular_with_node_id(2, MnType::Regular, |t: &mut ProRegTx| t.platform_node_id = Some(PlatformNodeId::default()))]
  #[case::regular_with_port(2, MnType::Regular, |t: &mut ProRegTx| t.platform_http_port = Some(1))]
  fn platform_fields_must_match_type_and_version(
    #[case] version: u16,
    #[case] mn_type: MnType,
    #[case] edit: fn(&mut ProRegTx),
  ) {
    let item = corpus_item(version, mn_type);
    assert_eq!(rebuild(&item, edit), Err(ProTxInvalid::BadPlatformFields));
  }

  #[rstest]
  fn deserialization_goes_through_new() {
    let item = corpus_item(2, MnType::Evo);
    let json = to_json(&item).replace("\"platformP2PPort\":", "\"platformP2PPort\":null,\"unused\":");
    assert!(json_rejects::<ProRegTx>(&json));
  }

  #[rstest]
  fn non_canonical_operator_key_is_a_null_key() {
    let mut item = corpus_item(2, MnType::Regular);
    assert_eq!(item.check(), None);
    item.pub_key_operator = item.pub_key_operator.corrupted();
    assert_eq!(item.check(), Some(ProTxInvalid::NullKey));
  }
}
