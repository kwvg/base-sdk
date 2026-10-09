//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! ProUpServTx service-update payload (type 2).

use super::proregtx::check_platform_fields;
use super::{
  check_sptx_netinfo, decode_version, encode_net_info, payload_hash, InputsHash, MnType, NetInfoForm, ProTxInvalid,
  PROTX_VERSION_BASIC_BLS, PROTX_VERSION_EXT_ADDR,
};
use crate::codec::impl_payload;
use crate::payload::PlatformNodeId;
use crate::types::{BlsScheme, BlsSig, NITrait, NetInfo, NetInfoV1, NetInfoV2, Routing, ServiceV1};
use crate::TxHash;

use bitcoin_primitives::script::ScriptPubKeyBuf;
use dash_num::Hash256;
use dash_pkc::bls::BLS_SIG_LEN;
use dash_types::codec::{BaseCodec, DecodeError, EncodeBuf};
use dash_types::Hashable;
use dash_types::{type_id::TypeId, Checkable, Numeric};

use core::fmt;

/// ProUpServTx -- update MN service addr (type 2).
///
/// - v1: LegacyBLS (no mn_type field)
/// - v2: BasicBLS (adds mn_type)
/// - v3: ExtAddr (extended network info)
///
/// The version-coupled fields are private, so [`ProUpServTx::new`] keeps them
/// in step with the version and masternode type.
#[derive(Clone, Debug, Eq, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase", try_from = "__ProUpServFields"))]
pub struct ProUpServTx {
  version: u16,
  mn_type: MnType,
  /// ProTx hash identifying the masternode.
  pub pro_tx_hash: TxHash,
  net_info: NetInfo,
  /// Operator payout script.
  pub script_operator_payout: ScriptPubKeyBuf,
  /// Hash of all inputs.
  pub inputs_hash: InputsHash,
  platform_node_id: Option<PlatformNodeId>,
  #[cfg_attr(feature = "serde", serde(rename = "platformP2PPort"))]
  platform_p2p_port: Option<u16>,
  #[cfg_attr(feature = "serde", serde(rename = "platformHTTPPort"))]
  platform_http_port: Option<u16>,
  sig: BlsSig,
}

impl_payload!(ProUpServTx);

impl BaseCodec for ProUpServTx {
  fn decode(data: &mut &[u8]) -> Result<Self, DecodeError> {
    let version = decode_version(data)?;

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
    self.encode_unsigned(NetInfoForm::Wire, buf);
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

    if let Some(e) = self.check_fields() {
      return Some(e);
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

    None
  }
}

/// The hash leaves out the operator signature, which signs the hash, and
/// covers the net info in its canonical encoding.
impl Hashable for ProUpServTx {
  type Hash = Hash256;

  fn hash(&self) -> Hash256 {
    payload_hash(|buf| self.encode_unsigned(NetInfoForm::Hash, buf))
  }
}

impl ProUpServTx {
  fn encode_unsigned(&self, form: NetInfoForm, buf: &mut impl EncodeBuf) {
    self.version.encode(buf);
    if self.version >= 2 {
      self.mn_type.to_base().encode(buf);
    }
    self.pro_tx_hash.encode(buf);
    encode_net_info(&self.net_info, form, buf);
    self.script_operator_payout.encode(buf);
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
  }

  /// Builds a service update whose masternode type, net info and platform
  /// fields match the version. The version selects the scheme of `sig`.
  ///
  /// # Errors
  ///
  /// Returns [`ProTxInvalid::EvoVersionTooLow`] or [`ProTxInvalid::BadMnType`]
  /// for a version 1 type other than regular, which version 1 cannot encode,
  /// [`ProTxInvalid::NetInfoVersionMismatch`], or
  /// [`ProTxInvalid::BadPlatformFields`].
  #[expect(clippy::too_many_arguments, reason = "one argument per wire field")]
  pub fn new(
    version: u16,
    mn_type: MnType,
    pro_tx_hash: TxHash,
    net_info: NetInfo,
    script_operator_payout: ScriptPubKeyBuf,
    inputs_hash: InputsHash,
    platform_node_id: Option<PlatformNodeId>,
    platform_p2p_port: Option<u16>,
    platform_http_port: Option<u16>,
    sig: [u8; BLS_SIG_LEN],
  ) -> Result<Self, ProTxInvalid> {
    let protx = Self {
      version,
      mn_type,
      pro_tx_hash,
      net_info,
      script_operator_payout,
      inputs_hash,
      platform_node_id,
      platform_p2p_port,
      platform_http_port,
      sig: BlsSig::from_bytes(sig, BlsScheme::from_protx_version(version)),
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

  /// Masternode type, always regular at version 1.
  pub const fn mn_type(&self) -> MnType {
    self.mn_type
  }

  /// Network addresses, legacy before version 3 and extended from it.
  pub const fn net_info(&self) -> &NetInfo {
    &self.net_info
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

  /// Operator BLS signature, in the scheme the version selects.
  pub const fn sig(&self) -> &BlsSig {
    &self.sig
  }

  /// Rejects a service address that `routing` does not admit.
  pub fn check_routing(&self, routing: Routing) -> Option<ProTxInvalid> {
    self
      .net_info
      .check_routing(routing)
      .map(|error| ProTxInvalid::NetInfoInvalid { error })
  }

  fn check_fields(&self) -> Option<ProTxInvalid> {
    if self.version < PROTX_VERSION_BASIC_BLS {
      match self.mn_type {
        MnType::Regular => {}
        MnType::Evo => return Some(ProTxInvalid::EvoVersionTooLow { version: self.version }),
        MnType::Unknown(_) => return Some(ProTxInvalid::BadMnType { mn_type: self.mn_type }),
      }
    }
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

/// Field set that builds a deserialized update through [`ProUpServTx::new`].
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
impl TryFrom<__ProUpServFields> for ProUpServTx {
  type Error = ProTxInvalid;

  fn try_from(fields: __ProUpServFields) -> Result<Self, Self::Error> {
    Self::new(
      fields.version,
      fields.mn_type,
      fields.pro_tx_hash,
      fields.net_info,
      fields.script_operator_payout,
      fields.inputs_hash,
      fields.platform_node_id,
      fields.platform_p2p_port,
      fields.platform_http_port,
      fields.sig,
    )
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
  use crate::types::{AddrV1, NIError};

  use dash_dev::{assert_serde_rt, check_sptx, json_rejects, to_json, Corpus};
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

  /// Rebuilds `item` through [`ProUpServTx::new`] after `edit` changes it.
  fn rebuild(item: &ProUpServTx, edit: impl FnOnce(&mut ProUpServTx)) -> Result<ProUpServTx, ProTxInvalid> {
    let mut t = item.clone();
    edit(&mut t);
    ProUpServTx::new(
      t.version,
      t.mn_type,
      t.pro_tx_hash,
      t.net_info,
      t.script_operator_payout,
      t.inputs_hash,
      t.platform_node_id,
      t.platform_p2p_port,
      t.platform_http_port,
      *t.sig.as_bytes(),
    )
  }

  #[rstest]
  #[case::regular_v1(1, MnType::Regular)]
  #[case::regular_v2(2, MnType::Regular)]
  #[case::evo_v2(2, MnType::Evo)]
  #[case::evo_v3(3, MnType::Evo)]
  fn consistent_payloads_rebuild_unchanged(#[case] version: u16, #[case] mn_type: MnType) {
    let item = corpus_item(version, mn_type);
    assert_eq!(rebuild(&item, |_| {}), Ok(item.clone()));
    assert_eq!(
      (item.version(), item.mn_type(), item.net_info(), item.sig()),
      (item.version, item.mn_type, &item.net_info, &item.sig)
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

  #[rstest]
  #[case::evo(MnType::Evo, ProTxInvalid::EvoVersionTooLow { version: 1 })]
  #[case::unknown(MnType::Unknown(7), ProTxInvalid::BadMnType { mn_type: MnType::Unknown(7) })]
  fn version_one_is_regular_only(#[case] mn_type: MnType, #[case] error: ProTxInvalid) {
    let item = corpus_item(1, MnType::Regular);
    assert_eq!(rebuild(&item, |t| t.mn_type = mn_type), Err(error));
  }

  #[rstest]
  fn legacy_service_with_an_invalid_address_is_rejected_as_empty() {
    let item = corpus_item(2, MnType::Regular);
    let service = ServiceV1 {
      addr: AddrV1([0; 16]),
      port: 9999,
    };
    let built = rebuild(&item, |t| t.net_info = NetInfo::Legacy(NetInfoV1(service)));
    assert_eq!(built.map(|t| t.check()), Ok(Some(ProTxInvalid::NetInfoEmpty)));
  }

  #[rstest]
  fn private_service_is_unroutable() {
    let item = corpus_item(2, MnType::Regular);
    assert_eq!(item.check_routing(Routing::Required), None);
    let service = ServiceV1 {
      addr: AddrV1([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 192, 168, 0, 1]),
      port: 9999,
    };
    let built = rebuild(&item, |t| t.net_info = NetInfo::Legacy(NetInfoV1(service)));
    assert_eq!(
      built.map(|t| t.check_routing(Routing::Required)),
      Ok(Some(ProTxInvalid::NetInfoInvalid {
        error: NIError::NotRoutable
      }))
    );
  }

  #[rstest]
  fn net_info_must_match_the_version() {
    let v2 = corpus_item(2, MnType::Evo);
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
  #[case::evo_v2_without_node_id(2, MnType::Evo, |t: &mut ProUpServTx| t.platform_node_id = None)]
  #[case::evo_v2_without_p2p_port(2, MnType::Evo, |t: &mut ProUpServTx| t.platform_p2p_port = None)]
  #[case::evo_v3_with_ports(3, MnType::Evo, |t: &mut ProUpServTx| t.platform_http_port = Some(1))]
  #[case::regular_with_node_id(2, MnType::Regular, |t: &mut ProUpServTx| t.platform_node_id = Some(PlatformNodeId::default()))]
  fn platform_fields_must_match_type_and_version(
    #[case] version: u16,
    #[case] mn_type: MnType,
    #[case] edit: fn(&mut ProUpServTx),
  ) {
    let item = corpus_item(version, mn_type);
    assert_eq!(rebuild(&item, edit), Err(ProTxInvalid::BadPlatformFields));
  }

  #[rstest]
  fn signature_takes_the_scheme_of_the_version() {
    let v1 = corpus_item(1, MnType::Regular);
    let rebuilt = rebuild(&v1, |_| {});
    assert_eq!(rebuilt.map(|t| t.sig().scheme()), Ok(BlsScheme::Legacy));
  }

  #[rstest]
  fn deserialization_goes_through_new() {
    let item = corpus_item(2, MnType::Evo);
    let json = to_json(&item).replace("\"platformP2PPort\":", "\"platformP2PPort\":null,\"unused\":");
    assert!(json_rejects::<ProUpServTx>(&json));
  }

  #[rstest]
  fn corpus_proupservtx() {
    let corpus = Corpus::open(env!("CARGO_MANIFEST_DIR"), "proupservtx");
    let items = corpus.entries::<ProUpServTx>("proupservtx", check_sptx);
    assert_serde_rt("proupservtx", &items);
  }

  /// The corpus holds the version 3 registration these updates refer to. Each
  /// operator signature verifies under the registered operator key over the
  /// hash without the signature, which covers the extended net info.
  #[rstest]
  fn operator_signature_verifies_over_the_payload_hash() {
    use crate::ProRegTx;

    use dash_pkc::bls::{BlsPublicKey, BlsScIetf, BlsSigId, BlsSignature};
    use dash_types::Hashable;

    let registrations =
      Corpus::open(env!("CARGO_MANIFEST_DIR"), "proregtx").entries::<ProRegTx>("proregtx", |_, _, _| {});
    let updates =
      Corpus::open(env!("CARGO_MANIFEST_DIR"), "proupservtx").entries::<ProUpServTx>("proupservtx", |_, _, _| {});
    let mut verified = 0;
    for (label, update) in &updates {
      let Some(registration) = registrations.get(&update.pro_tx_hash.to_string()) else {
        continue;
      };
      assert_eq!(update.version, 3, "{label}");
      let key = BlsPublicKey::<BlsScIetf>::from_bytes(registration.pub_key_operator().as_bytes());
      let sig = BlsSignature::<BlsScIetf>::from_bytes(update.sig.as_bytes());
      let hash = *update.hash().as_bytes();
      let verifies = |hash: &[u8]| match (&key, &sig) {
        (Ok(key), Ok(sig)) => key.verify_with(hash, sig, BlsSigId::Basic).is_ok(),
        _ => false,
      };
      assert!(verifies(&hash), "{label}");
      let mut signed = Vec::new();
      update.encode(&mut signed);
      assert!(
        !verifies(&bitcoin_hashes::sha256d::Hash::hash(&signed).to_byte_array()),
        "{label}"
      );
      verified += 1;
    }
    assert_eq!(verified, 3);
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
