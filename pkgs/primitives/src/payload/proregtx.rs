//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! ProRegTx registration payload (type 1).

use super::protx::{
  check_payout_list, decode_u8_list, encode_u8_count, encode_u8_list, legacy_payout_list, MAX_U8_LIST_LEN,
};
use super::{
  check_sptx_netinfo, decode_version, encode_net_info, payload_hash, CollateralShare, CompactSignature, InputsHash,
  MasternodePayoutShare, MnType, NetInfoForm, ProTxInvalid, MAX_OPERATOR_REWARD, PROTX_VERSION_BASIC_BLS,
  PROTX_VERSION_EXT_ADDR,
};
use crate::codec::impl_payload;
use crate::payload::PlatformNodeId;
use crate::prelude::*;
use crate::types::{BlsPubKey, BlsScheme, NITrait, NetInfo, NetInfoV1, NetInfoV2, Routing, ServiceV1};
use crate::{Transaction, TxHash, TxOut};

use bitcoin_primitives::script::ScriptPubKeyBuf;
use bitcoin_units::Amount;
use dash_num::Hash256;
use dash_pkc::bls::BLS_PK_LEN;
use dash_script::{is_shared_collateral_script, AddrParams, PubKeyHash, Recipient};
use dash_types::codec::{BaseCodec, DecodeError, EncodeBuf};
use dash_types::type_id::TypeId;
use dash_types::Hashable;
use dash_types::{Checkable, CompactSize, Numeric};
use hex_conservative::DisplayHex;

use core::fmt;

/// ProRegTx -- register a new masternode (type 1).
///
/// - v1: LegacyBLS
/// - v2: BasicBLS
/// - v3: ExtAddr (extended network info, payout list and collateral shares)
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
  script_payout: ScriptPubKeyBuf,
  payouts: Vec<MasternodePayoutShare>,
  shares: Vec<(CollateralShare, CompactSignature)>,
  early_period_blocks: u32,
  early_penalty: i64,
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

/// Checks the collateral shares of a shared registration and its early terms.
/// No refund or reward script may pay the voting key or any share's owner.
fn check_share_list<'a>(
  shares: impl Iterator<Item = &'a CollateralShare> + Clone,
  early_period_blocks: u32,
  early_penalty: i64,
  required: Amount,
  voting: &PubKeyHash,
) -> Option<ProTxInvalid> {
  let count = shares.clone().count();
  if !(ProRegTx::MIN_SHARES..=ProRegTx::MAX_SHARES).contains(&count) {
    return Some(ProTxInvalid::BadShareCount { count });
  }
  if early_period_blocks > ProRegTx::MAX_EARLY_PERIOD_BLOCKS {
    return Some(ProTxInvalid::BadEarlyPeriod {
      blocks: early_period_blocks,
    });
  }

  let required = i64::try_from(required.to_sat()).unwrap_or(i64::MAX);
  let mut total = 0i64;
  let mut min_amount = i64::MAX;
  let mut owners = BTreeSet::new();
  let mut refunds = BTreeSet::new();
  for share in shares.clone() {
    // Each amount is at most `required`, so the total of at most eight
    // shares cannot overflow.
    if !(CollateralShare::MIN_AMOUNT..=required).contains(&share.amount) {
      return Some(ProTxInvalid::BadShareAmount { amount: share.amount });
    }
    total += share.amount;
    min_amount = min_amount.min(share.amount);

    if share.key_id_owner.is_null() {
      return Some(ProTxInvalid::NullShareKey);
    }
    if !owners.insert(share.key_id_owner) {
      return Some(ProTxInvalid::DuplicateShareKey);
    }
    if !refunds.insert(share.script_refund.as_bytes()) {
      return Some(ProTxInvalid::DuplicateShareRefund);
    }

    // An empty reward script pays the refund script.
    let reward = Some(&share.script_reward).filter(|script| !script.is_empty());
    for script in core::iter::once(&share.script_refund).chain(reward) {
      let recipient = Recipient::from_script(script.as_bytes());
      if !matches!(recipient, Some(Recipient::PubKeyHash(_) | Recipient::ScriptHash(_))) {
        return Some(ProTxInvalid::BadSharePayee);
      }
      if let Some(Recipient::PubKeyHash(hash)) = &recipient {
        if hash == voting || shares.clone().any(|other| other.key_id_owner == *hash) {
          return Some(ProTxInvalid::SharePayeeReuse);
        }
      }
    }
  }

  if total != required {
    return Some(ProTxInvalid::BadShareAmountSum { total });
  }
  // Without an early period the penalty still caps the unilateral bonus, so
  // it must be zero.
  if early_penalty < 0 || early_penalty >= min_amount || (early_period_blocks == 0 && early_penalty != 0) {
    return Some(ProTxInvalid::BadSharePenalty { penalty: early_penalty });
  }
  None
}

/// Prefix of the shared registration consent message.
const CONSENT_PREFIX: [u8; 15] = *b"DashSharedMNReg";

/// Core P2P port of mainnet, which platform ports may not take on any network.
const MAINNET_CORE_PORT: u16 = 9999;

/// Checks the values of the platform fields that the masternode type and the
/// version require. Ports carried before version 3 must differ from the
/// mainnet core port, from each other and from `core_port`.
pub(super) fn check_platform_values(
  platform_node_id: Option<PlatformNodeId>,
  platform_ports: Option<(u16, u16)>,
  core_port: u16,
) -> Option<ProTxInvalid> {
  if platform_node_id.is_some_and(|node_id| node_id.is_null()) {
    return Some(ProTxInvalid::NullPlatformNodeId);
  }
  let (p2p, http) = platform_ports?;
  if p2p == MAINNET_CORE_PORT {
    return Some(ProTxInvalid::BadPlatformP2pPort { port: p2p });
  }
  if http == MAINNET_CORE_PORT {
    return Some(ProTxInvalid::BadPlatformHttpPort { port: http });
  }
  (p2p == http || p2p == core_port || http == core_port).then_some(ProTxInvalid::DuplicatePlatformPorts)
}

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
    let (script_payout, payouts, shares, early_period_blocks, early_penalty) = if version >= PROTX_VERSION_EXT_ADDR {
      let payouts = decode_u8_list(data)?;
      let shares: Vec<CollateralShare> = decode_u8_list(data)?;
      let join_sigs = (0..shares.len())
        .map(|_| CompactSignature::decode(data))
        .collect::<Result<Vec<_>, _>>()?;
      let shares = shares.into_iter().zip(join_sigs).collect();
      (
        ScriptPubKeyBuf::new(),
        payouts,
        shares,
        u32::decode(data)?,
        i64::decode(data)?,
      )
    } else {
      (ScriptPubKeyBuf::decode(data)?, Vec::new(), Vec::new(), 0, 0)
    };
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
      payouts,
      shares,
      early_period_blocks,
      early_penalty,
      inputs_hash,
      platform_node_id,
      platform_p2p_port,
      platform_http_port,
      vch_sig: Vec::decode(data)?,
    })
  }

  fn encode(&self, buf: &mut impl EncodeBuf) {
    self.encode_unsigned(NetInfoForm::Wire, buf);
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

    if self.is_shared() {
      if !self.collateral_hash.is_null() {
        return Some(ProTxInvalid::SharesExternal);
      }
      if !self.key_id_owner.is_null() {
        return Some(ProTxInvalid::SharesOwnerKey);
      }
      if !self.payouts.is_empty() {
        return Some(ProTxInvalid::SharesPayouts);
      }
    } else {
      if self.early_period_blocks != 0 || self.early_penalty != 0 {
        return Some(ProTxInvalid::SharesEmptyFields);
      }
      if self.key_id_owner.is_null() {
        return Some(ProTxInvalid::NullKey);
      }
    }
    // A non-canonical operator key is an invalid key, reported as null.
    if self.pub_key_operator.is_null() || !self.pub_key_operator.is_canonical() || self.key_id_voting.is_null() {
      return Some(ProTxInvalid::NullKey);
    }

    if let Some(e) = self.check_owner_payouts() {
      return Some(e);
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

    if self.operator_reward > MAX_OPERATOR_REWARD {
      return Some(ProTxInvalid::OperatorRewardTooHigh {
        reward: self.operator_reward,
      });
    }

    check_platform_values(
      self.platform_node_id,
      self.platform_p2p_port.zip(self.platform_http_port),
      self.net_info.primary().map_or(0, |service| service.port),
    )
  }
}

/// The hash leaves out the owner signature, which signs the hash, and covers
/// the net info in its canonical encoding.
impl Hashable for ProRegTx {
  type Hash = Hash256;

  fn hash(&self) -> Hash256 {
    payload_hash(|buf| self.encode_unsigned(NetInfoForm::Hash, buf))
  }
}

impl ProRegTx {
  /// Fewest collateral shares a shared registration holds.
  pub const MIN_SHARES: usize = 2;

  /// Most collateral shares a shared registration holds.
  pub const MAX_SHARES: usize = 8;

  /// Longest early period in blocks, about two years of blocks.
  pub const MAX_EARLY_PERIOD_BLOCKS: u32 = 420_480;

  fn encode_unsigned(&self, form: NetInfoForm, buf: &mut impl EncodeBuf) {
    self.version.encode(buf);
    self.mn_type.to_base().encode(buf);
    self.mode.encode(buf);
    self.collateral_hash.encode(buf);
    self.collateral_index.encode(buf);
    encode_net_info(&self.net_info, form, buf);
    self.key_id_owner.encode(buf);
    self.pub_key_operator.encode(buf);
    self.key_id_voting.encode(buf);
    self.operator_reward.encode(buf);
    if self.version >= PROTX_VERSION_EXT_ADDR {
      encode_u8_list(&self.payouts, buf);
      encode_u8_count(self.shares.len(), buf);
      for (share, _) in &self.shares {
        share.encode(buf);
      }
      for (_, join_sig) in &self.shares {
        join_sig.encode(buf);
      }
      self.early_period_blocks.encode(buf);
      self.early_penalty.encode(buf);
    } else {
      self.script_payout.encode(buf);
    }
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

  /// Builds a registration whose net info, payout and platform fields match
  /// the version and masternode type. The version selects the scheme of
  /// `pub_key_operator`.
  ///
  /// # Errors
  ///
  /// Returns [`ProTxInvalid::NetInfoVersionMismatch`],
  /// [`ProTxInvalid::BadPayoutFields`] or [`ProTxInvalid::BadPlatformFields`]
  /// for a field that does not match.
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
    payouts: Vec<MasternodePayoutShare>,
    shares: Vec<(CollateralShare, CompactSignature)>,
    early_period_blocks: u32,
    early_penalty: i64,
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
      payouts,
      shares,
      early_period_blocks,
      early_penalty,
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

  /// Whether collateral shares fund the registration.
  pub fn is_shared(&self) -> bool {
    !self.shares.is_empty()
  }

  /// Payout script, empty from version 3.
  pub const fn script_payout(&self) -> &ScriptPubKeyBuf {
    &self.script_payout
  }

  /// Owner payout list, empty before version 3.
  pub fn payouts(&self) -> &[MasternodePayoutShare] {
    &self.payouts
  }

  /// Collateral shares, each with the join signature of its owner, empty
  /// before version 3.
  pub fn shares(&self) -> &[(CollateralShare, CompactSignature)] {
    &self.shares
  }

  /// Length in blocks of the early period after registration, 0 before
  /// version 3.
  pub const fn early_period_blocks(&self) -> u32 {
    self.early_period_blocks
  }

  /// Early dissolution penalty in duffs, 0 before version 3.
  pub const fn early_penalty(&self) -> i64 {
    self.early_penalty
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

  /// Rejects a service address that `routing` does not admit. An empty net
  /// info has no address to route.
  pub fn check_routing(&self, routing: Routing) -> Option<ProTxInvalid> {
    if self.net_info.is_empty() {
      return None;
    }
    self
      .net_info
      .check_routing(routing)
      .map(|error| ProTxInvalid::NetInfoInvalid { error })
  }

  /// Rejects a shared registration whose collateral output, among the
  /// transaction's `outputs`, does not pay the shared collateral script.
  pub(crate) fn check_shared_collateral(&self, outputs: &[TxOut]) -> Option<ProTxInvalid> {
    if !self.is_shared() {
      return None;
    }
    let collateral = usize::try_from(self.collateral_index)
      .ok()
      .and_then(|index| outputs.get(index));
    let pays_template = collateral.is_some_and(|output| is_shared_collateral_script(output.script_pubkey.as_bytes()));
    (!pays_template).then_some(ProTxInvalid::SharesCollateralScript)
  }

  /// Hash each share owner signs to join the shared registration in `tx`.
  /// It covers the inputs, sequences and outputs of `tx`, the share table,
  /// the early terms and the registrar fields.
  pub fn consent_hash(&self, tx: &Transaction) -> Hash256 {
    payload_hash(|buf| {
      CompactSize::from(CONSENT_PREFIX.len()).encode(buf);
      CONSENT_PREFIX.encode(buf);
      self.version.encode(buf);
      tx.version.encode(buf);
      tx.tx_type.to_base().encode(buf);
      tx.lock_time.encode(buf);
      tx.inputs_hash().encode(buf);
      for input in &tx.inputs {
        input.sequence.encode(buf);
      }
      tx.outputs_hash().encode(buf);
      self.mn_type.to_base().encode(buf);
      self.mode.encode(buf);
      encode_net_info(&self.net_info, NetInfoForm::Hash, buf);
      if let Some(node_id) = self.platform_node_id {
        node_id.encode(buf);
      }
      self.key_id_voting.encode(buf);
      self.pub_key_operator.encode(buf);
      self.operator_reward.encode(buf);
      encode_u8_count(self.shares.len(), buf);
      for (share, _) in &self.shares {
        share.encode(buf);
      }
      self.early_period_blocks.encode(buf);
      self.early_penalty.encode(buf);
    })
  }

  /// Message the collateral key signs for an external collateral, under the
  /// address prefixes of `params`. From version 3 it lists every owner
  /// payout with its reward.
  pub fn sign_string(&self, params: &AddrParams) -> String {
    let address = |script: &ScriptPubKeyBuf| {
      Recipient::from_script(script.as_bytes())
        .and_then(|recipient| recipient.to_base58c(params))
        .unwrap_or_else(|| script.as_bytes().to_lower_hex_string())
    };
    let payout = if self.version >= PROTX_VERSION_EXT_ADDR {
      let entries: Vec<String> = self
        .payouts
        .iter()
        .map(|payout| format!("{}:{}", address(&payout.script_payout), payout.reward))
        .collect();
      entries.join(",")
    } else {
      address(&self.script_payout)
    };
    format!(
      "{payout}|{}|{}|{}|{}",
      self.operator_reward,
      self.key_id_owner.to_base58c(params.pubkey_addr),
      self.key_id_voting.to_base58c(params.pubkey_addr),
      self.hash()
    )
  }

  fn check_owner_payouts(&self) -> Option<ProTxInvalid> {
    if self.is_shared() {
      let Some(required) = self.mn_type.collateral_amount() else {
        return Some(ProTxInvalid::BadMnType { mn_type: self.mn_type });
      };
      return check_share_list(
        self.shares.iter().map(|(share, _)| share),
        self.early_period_blocks,
        self.early_penalty,
        required,
        &self.key_id_voting,
      );
    }
    let owner = Some(&self.key_id_owner);
    if self.version >= PROTX_VERSION_EXT_ADDR {
      check_payout_list(&self.payouts, owner, &self.key_id_voting)
    } else {
      check_payout_list(&legacy_payout_list(&self.script_payout), owner, &self.key_id_voting)
    }
  }

  fn check_fields(&self) -> Option<ProTxInvalid> {
    let is_extended = matches!(self.net_info, NetInfo::Extended(_));
    if is_extended != (self.version >= PROTX_VERSION_EXT_ADDR) {
      return Some(ProTxInvalid::NetInfoVersionMismatch);
    }
    let fits_layout = if self.version >= PROTX_VERSION_EXT_ADDR {
      self.script_payout.is_empty() && self.payouts.len() <= MAX_U8_LIST_LEN && self.shares.len() <= MAX_U8_LIST_LEN
    } else {
      self.payouts.is_empty() && self.shares.is_empty() && self.early_period_blocks == 0 && self.early_penalty == 0
    };
    if !fits_layout {
      return Some(ProTxInvalid::BadPayoutFields);
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
  #[serde(default)]
  script_payout: ScriptPubKeyBuf,
  #[serde(default)]
  payouts: Vec<MasternodePayoutShare>,
  #[serde(default)]
  shares: Vec<(CollateralShare, CompactSignature)>,
  #[serde(default)]
  early_period_blocks: u32,
  #[serde(default)]
  early_penalty: i64,
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
      fields.payouts,
      fields.shares,
      fields.early_period_blocks,
      fields.early_penalty,
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
  use crate::payload::protx::testing::signer;
  use crate::types::{AddrV1, NIError, NIPurpose};
  use crate::{PayloadInvalid, Transaction, TxInvalid};

  use dash_dev::{assert_serde_rt, check_sptx, from_json, json_rejects, to_json, Corpus};
  use dash_script::{AddrParams, SHARED_COLLATERAL_SCRIPT};
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
  fn corpus_shared_registrations() {
    let corpus = Corpus::open(env!("CARGO_MANIFEST_DIR"), "proregtx");
    let items = corpus.entries::<ProRegTx>("proregtx_shared", check_sptx);
    assert_serde_rt("proregtx_shared", &items);
    let counts: BTreeSet<usize> = items.values().map(|item| item.shares().len()).collect();
    assert_eq!(counts, BTreeSet::from([2, 8]));
    assert!(items.values().all(ProRegTx::is_shared));
  }

  /// The first two-share regular registration of the corpus.
  fn shared_item() -> ProRegTx {
    let corpus = Corpus::open(env!("CARGO_MANIFEST_DIR"), "proregtx");
    let items = corpus.entries::<ProRegTx>("proregtx_shared", |_, _, _| {});
    let mut items = items
      .into_values()
      .filter(|item| item.mn_type == MnType::Regular && item.shares.len() == 2);
    let item = items.next();
    assert!(item.is_some());
    item.unwrap_or_else(|| corpus_item(3, MnType::Regular))
  }

  fn p2pkh(hash: &PubKeyHash) -> ScriptPubKeyBuf {
    let mut script = hex!("76a914").to_vec();
    script.extend(hash.to_lendian());
    script.extend(hex!("88ac"));
    ScriptPubKeyBuf::from_bytes(script)
  }

  const DASH: i64 = 100_000_000;

  #[rstest]
  #[case::external(|t: &mut ProRegTx| t.collateral_hash = TxHash::from_lendian([1; 32]), ProTxInvalid::SharesExternal)]
  #[case::owner_key(|t: &mut ProRegTx| t.key_id_owner = PubKeyHash::from_lendian([1; 20]), ProTxInvalid::SharesOwnerKey)]
  #[case::payouts(|t: &mut ProRegTx| t.payouts = vec![MasternodePayoutShare { script_payout: ScriptPubKeyBuf::new(), reward: 1 }], ProTxInvalid::SharesPayouts)]
  #[case::null_voting(|t: &mut ProRegTx| t.key_id_voting = PubKeyHash::default(), ProTxInvalid::NullKey)]
  #[case::one_share(|t: &mut ProRegTx| { t.shares.truncate(1); }, ProTxInvalid::BadShareCount { count: 1 })]
  #[case::nine_shares(|t: &mut ProRegTx| t.shares = vec![t.shares[0].clone(); 9], ProTxInvalid::BadShareCount { count: 9 })]
  #[case::early_period(|t: &mut ProRegTx| t.early_period_blocks = 420_481, ProTxInvalid::BadEarlyPeriod { blocks: 420_481 })]
  #[case::amount_low(|t: &mut ProRegTx| t.shares[0].0.amount = 100 * DASH - 1, ProTxInvalid::BadShareAmount { amount: 100 * DASH - 1 })]
  #[case::amount_high(|t: &mut ProRegTx| t.shares[1].0.amount = 1000 * DASH + 1, ProTxInvalid::BadShareAmount { amount: 1000 * DASH + 1 })]
  #[case::null_share_key(|t: &mut ProRegTx| t.shares[1].0.key_id_owner = PubKeyHash::default(), ProTxInvalid::NullShareKey)]
  #[case::dup_key(|t: &mut ProRegTx| t.shares[1].0.key_id_owner = t.shares[0].0.key_id_owner, ProTxInvalid::DuplicateShareKey)]
  #[case::dup_refund(|t: &mut ProRegTx| t.shares[1].0.script_refund = t.shares[0].0.script_refund.clone(), ProTxInvalid::DuplicateShareRefund)]
  #[case::bad_refund(|t: &mut ProRegTx| t.shares[0].0.script_refund = ScriptPubKeyBuf::from_bytes(vec![0x51]), ProTxInvalid::BadSharePayee)]
  #[case::bad_reward(|t: &mut ProRegTx| t.shares[0].0.script_reward = ScriptPubKeyBuf::from_bytes(vec![0x51]), ProTxInvalid::BadSharePayee)]
  #[case::refund_pays_voting(|t: &mut ProRegTx| t.shares[0].0.script_refund = p2pkh(&t.key_id_voting), ProTxInvalid::SharePayeeReuse)]
  #[case::reward_pays_other_owner(|t: &mut ProRegTx| t.shares[0].0.script_reward = p2pkh(&t.shares[1].0.key_id_owner), ProTxInvalid::SharePayeeReuse)]
  #[case::sum(|t: &mut ProRegTx| t.shares[0].0.amount -= 1, ProTxInvalid::BadShareAmountSum { total: 1000 * DASH - 1 })]
  #[case::negative_penalty(|t: &mut ProRegTx| t.early_penalty = -1, ProTxInvalid::BadSharePenalty { penalty: -1 })]
  #[case::penalty_at_min(|t: &mut ProRegTx| t.early_penalty = 400 * DASH, ProTxInvalid::BadSharePenalty { penalty: 400 * DASH })]
  #[case::penalty_without_period(|t: &mut ProRegTx| t.early_period_blocks = 0, ProTxInvalid::BadSharePenalty { penalty: 50 * DASH })]
  fn shared_registration_rules(#[case] edit: fn(&mut ProRegTx), #[case] error: ProTxInvalid) {
    let mut item = shared_item();
    assert_eq!(item.check(), None);
    assert_eq!(
      item.shares.iter().map(|(share, _)| share.amount).collect::<Vec<_>>(),
      [600 * DASH, 400 * DASH]
    );
    assert_eq!((item.early_period_blocks, item.early_penalty), (30, 50 * DASH));
    edit(&mut item);
    assert_eq!(item.check(), Some(error));
  }

  #[rstest]
  #[case::penalty_below_min(|t: &mut ProRegTx| t.early_penalty = 400 * DASH - 1)]
  #[case::no_terms(|t: &mut ProRegTx| (t.early_period_blocks, t.early_penalty) = (0, 0))]
  #[case::longest_period(|t: &mut ProRegTx| t.early_period_blocks = 420_480)]
  #[case::reward_script(|t: &mut ProRegTx| t.shares[0].0.script_reward = p2pkh(&PubKeyHash::from_lendian([7; 20])))]
  fn shared_registration_bounds(#[case] edit: fn(&mut ProRegTx)) {
    let mut item = shared_item();
    edit(&mut item);
    assert_eq!(item.check(), None);
  }

  #[rstest]
  #[case::early_period(|t: &mut ProRegTx| t.early_period_blocks = 1)]
  #[case::early_penalty(|t: &mut ProRegTx| t.early_penalty = 1)]
  fn single_owner_registration_has_no_early_terms(#[case] edit: fn(&mut ProRegTx)) {
    let mut item = corpus_item(3, MnType::Regular);
    edit(&mut item);
    assert_eq!(item.check(), Some(ProTxInvalid::SharesEmptyFields));
  }

  #[rstest]
  #[case::external(ProTxInvalid::SharesExternal, "bad-protx-shares-external")]
  #[case::owner_key(ProTxInvalid::SharesOwnerKey, "bad-protx-shares-owner-key")]
  #[case::payouts(ProTxInvalid::SharesPayouts, "bad-protx-shares-payouts")]
  #[case::empty_fields(ProTxInvalid::SharesEmptyFields, "bad-protx-shares-empty-fields")]
  #[case::count(ProTxInvalid::BadShareCount { count: 1 }, "bad-protx-shares-count: 1")]
  #[case::early_period(ProTxInvalid::BadEarlyPeriod { blocks: 1 }, "bad-protx-shares-early-period: 1")]
  #[case::amount(ProTxInvalid::BadShareAmount { amount: 1 }, "bad-protx-shares-amount: 1")]
  #[case::key_null(ProTxInvalid::NullShareKey, "bad-protx-shares-key-null")]
  #[case::dup_key(ProTxInvalid::DuplicateShareKey, "bad-protx-shares-dup-key")]
  #[case::dup_refund(ProTxInvalid::DuplicateShareRefund, "bad-protx-shares-dup-refund")]
  #[case::payee(ProTxInvalid::BadSharePayee, "bad-protx-shares-payee")]
  #[case::payee_reuse(ProTxInvalid::SharePayeeReuse, "bad-protx-shares-payee-reuse")]
  #[case::amount_sum(ProTxInvalid::BadShareAmountSum { total: 1 }, "bad-protx-shares-amount-sum: 1")]
  #[case::penalty(ProTxInvalid::BadSharePenalty { penalty: 1 }, "bad-protx-shares-penalty: 1")]
  fn share_reasons(#[case] error: ProTxInvalid, #[case] reason: &str) {
    assert_eq!(error.to_string(), reason);
  }

  /// A version 3 regular corpus payload changed by `edit`.
  fn v3_with(edit: impl FnOnce(&mut ProRegTx)) -> ProRegTx {
    let mut item = corpus_item(3, MnType::Regular);
    edit(&mut item);
    item
  }

  fn share(byte: u8) -> (CollateralShare, CompactSignature) {
    let share = CollateralShare {
      amount: 500 * 100_000_000,
      script_refund: ScriptPubKeyBuf::from_bytes(vec![byte; 3]),
      script_reward: ScriptPubKeyBuf::new(),
      key_id_owner: PubKeyHash::from_lendian([byte; 20]),
    };
    (share, CompactSignature::from_bytes([byte; 65]))
  }

  #[rstest]
  #[case::payouts(|t: &mut ProRegTx| t.payouts.clear())]
  #[case::shares(|t: &mut ProRegTx| t.shares = vec![share(1), share(2)])]
  #[case::early_terms(|t: &mut ProRegTx| (t.early_period_blocks, t.early_penalty) = (7, -1))]
  fn v3_terms_round_trip(#[case] edit: fn(&mut ProRegTx)) {
    let item = v3_with(edit);
    let mut buf = Vec::new();
    item.encode(&mut buf);
    assert_eq!(ProRegTx::decode(&mut buf.as_slice()), Ok(item.clone()));
    assert_eq!(rebuild(&item, |_| {}), Ok(item));
  }

  /// The hash covers the join signatures and leaves out the owner signature.
  #[rstest]
  fn hash_covers_join_signatures() {
    let item = v3_with(|t| t.shares = vec![share(1), share(2)]);
    let resigned = v3_with(|t| t.shares = vec![share(1), (share(2).0, CompactSignature::from_bytes([3; 65]))]);
    assert_ne!(item.hash(), resigned.hash());
    let owner_signed = v3_with(|t| {
      t.shares = vec![share(1), share(2)];
      t.vch_sig = vec![1; 65];
    });
    assert_eq!(item.hash(), owner_signed.hash());
  }

  #[rstest]
  fn join_signatures_follow_the_share_count() {
    let item = v3_with(|t| t.shares = vec![share(1), share(2)]);
    let mut buf = Vec::new();
    item.encode(&mut buf);
    let sigs_end = buf.len() - (4 + 8 + 32 + 1 + item.vch_sig.len());
    let truncated = &buf[..sigs_end - 1];
    assert!(matches!(
      ProRegTx::decode(&mut &truncated[..]),
      Err(DecodeError::Eof { .. })
    ));
  }

  #[rstest]
  #[case::v2_payouts(2, |t: &mut ProRegTx| t.payouts = vec![MasternodePayoutShare { script_payout: ScriptPubKeyBuf::new(), reward: 1 }])]
  #[case::v2_shares(2, |t: &mut ProRegTx| t.shares = vec![share(1)])]
  #[case::v2_early_period(2, |t: &mut ProRegTx| t.early_period_blocks = 1)]
  #[case::v2_early_penalty(2, |t: &mut ProRegTx| t.early_penalty = 1)]
  #[case::v3_script_payout(3, |t: &mut ProRegTx| t.script_payout = ScriptPubKeyBuf::from_bytes(vec![0x51]))]
  #[case::v3_256_payouts(3, |t: &mut ProRegTx| t.payouts = vec![t.payouts[0].clone(); 256])]
  #[case::v3_256_shares(3, |t: &mut ProRegTx| t.shares = vec![share(1); 256])]
  fn payout_fields_must_fit_the_layout(#[case] version: u16, #[case] edit: fn(&mut ProRegTx)) {
    let item = corpus_item(version, MnType::Regular);
    assert_eq!(rebuild(&item, edit), Err(ProTxInvalid::BadPayoutFields));
    assert_eq!(ProTxInvalid::BadPayoutFields.to_string(), "bad-protx-payout-fields");
  }

  #[rstest]
  fn v3_payout_lists_hold_255_entries() {
    let item = corpus_item(3, MnType::Regular);
    let built = rebuild(&item, |t| t.payouts = vec![t.payouts[0].clone(); 255]);
    let mut buf = Vec::new();
    if let Ok(t) = &built {
      t.encode(&mut buf);
    }
    assert_eq!(ProRegTx::decode(&mut buf.as_slice()).ok(), built.ok());
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
      t.payouts,
      t.shares,
      t.early_period_blocks,
      t.early_penalty,
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

  /// The address bytes stay as decoded, so the txid is unaffected.
  #[rstest]
  fn legacy_service_with_an_invalid_address_counts_as_empty() {
    let item = corpus_item(2, MnType::Regular);
    let service = ServiceV1 {
      addr: AddrV1([0; 16]),
      port: 9999,
    };
    let built = rebuild(&item, |t| t.net_info = NetInfo::Legacy(NetInfoV1(service)));
    assert_eq!(built.as_ref().map(|t| t.check()), Ok(None));

    let mut buf = Vec::new();
    if let Ok(t) = &built {
      t.encode(&mut buf);
    }
    assert_eq!(ProRegTx::decode(&mut buf.as_slice()).ok(), built.ok());
    // The service follows the version, type, mode and collateral outpoint.
    assert_eq!(
      buf[2 + 2 + 2 + 32 + 4..][..18],
      [&[0; 16][..], &9999u16.to_be_bytes()[..]].concat()
    );
  }

  #[rstest]
  fn legacy_service_must_be_ipv4() {
    let item = corpus_item(2, MnType::Regular);
    let service = ServiceV1 {
      addr: AddrV1(hex!("20010000000000000000000000000001")),
      port: 9999,
    };
    let built = rebuild(&item, |t| t.net_info = NetInfo::Legacy(NetInfoV1(service)));
    let error = NIError::BadType { entry_type: 2 };
    assert_eq!(
      built.as_ref().map(|t| t.check()),
      Ok(Some(ProTxInvalid::NetInfoInvalid { error }))
    );
    let reason = built.map(|t| t.check().map(|e| e.to_string()));
    assert!(matches!(reason, Ok(Some(r)) if r.starts_with("bad-protx-netinfo-addr-type")));
  }

  #[rstest]
  fn corpus_services_are_routable() {
    assert_eq!(corpus_item(2, MnType::Regular).check_routing(Routing::Required), None);
  }

  #[rstest]
  #[case::private(AddrV1(hex!("00000000000000000000ffff0a000001")), Some(ProTxInvalid::NetInfoInvalid { error: NIError::NotRoutable }))]
  #[case::empty(AddrV1([0; 16]), None)]
  fn routing_applies_to_non_empty_net_info(#[case] addr: AddrV1, #[case] expected: Option<ProTxInvalid>) {
    let item = corpus_item(2, MnType::Regular);
    let service = ServiceV1 { addr, port: 9999 };
    let built = rebuild(&item, |t| t.net_info = NetInfo::Legacy(NetInfoV1(service)));
    assert_eq!(built.as_ref().map(|t| t.check_routing(Routing::Required)), Ok(expected));
    assert_eq!(built.map(|t| t.check_routing(Routing::Any)), Ok(None));
  }

  #[rstest]
  fn corpus_net_info_is_already_canonical() {
    let corpus = Corpus::open(env!("CARGO_MANIFEST_DIR"), "proregtx");
    for (label, item) in corpus.entries::<ProRegTx>("proregtx", |_, _, _| {}) {
      let (mut wire, mut canonical) = (Vec::new(), Vec::new());
      match &item.net_info {
        NetInfo::Legacy(v1) => v1.encode(&mut wire),
        NetInfo::Extended(v2) => v2.encode(&mut wire),
      }
      item.net_info.encode_canonical(&mut canonical);
      assert_eq!(canonical, wire, "{label}");
    }
  }

  #[rstest]
  #[case::v2(2)]
  #[case::v3(3)]
  fn evo_platform_node_id_must_not_be_null(#[case] version: u16) {
    let item = corpus_item(version, MnType::Evo);
    assert_eq!(item.check(), None);
    let built = rebuild(&item, |t| t.platform_node_id = Some(PlatformNodeId::default()));
    assert_eq!(built.map(|t| t.check()), Ok(Some(ProTxInvalid::NullPlatformNodeId)));
    assert_eq!(
      ProTxInvalid::NullPlatformNodeId.to_string(),
      "bad-protx-platform-nodeid"
    );
  }

  #[rstest]
  #[case::p2p_mainnet_core(Some(9999), None, ProTxInvalid::BadPlatformP2pPort { port: 9999 })]
  #[case::http_mainnet_core(None, Some(9999), ProTxInvalid::BadPlatformHttpPort { port: 9999 })]
  #[case::same_ports(Some(4000), Some(4000), ProTxInvalid::DuplicatePlatformPorts)]
  #[case::p2p_is_core(Some(0), None, ProTxInvalid::DuplicatePlatformPorts)]
  #[case::http_is_core(None, Some(0), ProTxInvalid::DuplicatePlatformPorts)]
  fn evo_platform_ports_are_distinct_and_not_9999(
    #[case] p2p: Option<u16>,
    #[case] http: Option<u16>,
    #[case] error: ProTxInvalid,
  ) {
    let item = corpus_item(2, MnType::Evo);
    assert_eq!(item.check(), None);
    // The core port moves off the mainnet port, so the cases can collide
    // with it alone. A port of 0 in a case stands for the core port.
    const CORE: u16 = 4001;
    let port = |case: Option<u16>, current: Option<u16>| match case {
      Some(0) => Some(CORE),
      Some(port) => Some(port),
      None => current,
    };
    let built = rebuild(&item, |t| {
      if let NetInfo::Legacy(NetInfoV1(service)) = &mut t.net_info {
        service.port = CORE;
      }
      t.platform_p2p_port = port(p2p, t.platform_p2p_port);
      t.platform_http_port = port(http, t.platform_http_port);
    });
    assert_eq!(
      built.as_ref().map(|t| t.net_info.primary().map(|s| s.port)),
      Ok(Some(CORE))
    );
    assert_eq!(built.map(|t| t.check()), Ok(Some(error)));
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

  /// A payout that reuses the voting key fails ahead of an invalid service.
  #[rstest]
  #[case::v2(2)]
  #[case::v3(3)]
  fn owner_payouts_are_checked_before_net_info(#[case] version: u16) {
    let voting = PubKeyHash::from_lendian([0xa2; 20]);
    let mut script = hex!("76a914").to_vec();
    script.extend([0xa2; 20]);
    script.extend(hex!("88ac"));
    let reuse = ScriptPubKeyBuf::from_bytes(script);
    let mut item = corpus_item(version, MnType::Regular);
    item.key_id_voting = voting;
    if version >= PROTX_VERSION_EXT_ADDR {
      item.payouts = vec![MasternodePayoutShare {
        script_payout: reuse,
        reward: MasternodePayoutShare::MAX_REWARD,
      }];
    } else {
      item.script_payout = reuse;
    }
    assert_eq!(item.check(), Some(ProTxInvalid::PayoutKeyReuse));
    item.net_info = match item.net_info {
      NetInfo::Legacy(_) => NetInfo::Legacy(NetInfoV1(ServiceV1 {
        addr: AddrV1(hex!("20010000000000000000000000000001")),
        port: 9999,
      })),
      NetInfo::Extended(_) => NetInfo::Extended(NetInfoV2::new(vec![(NIPurpose::CoreP2p, vec![])])),
    };
    assert!(!item.net_info.is_empty());
    assert_eq!(item.check(), Some(ProTxInvalid::PayoutKeyReuse));
  }

  #[rstest]
  fn non_canonical_operator_key_is_a_null_key() {
    let mut item = corpus_item(2, MnType::Regular);
    assert_eq!(item.check(), None);
    item.pub_key_operator = item.pub_key_operator.corrupted();
    assert_eq!(item.check(), Some(ProTxInvalid::NullKey));
  }

  /// The corpus shared registrations, each in its transaction.
  fn shared_transactions() -> Vec<(Transaction, ProRegTx)> {
    let corpus = Corpus::open(env!("CARGO_MANIFEST_DIR"), "proregtx");
    let mut txs = Vec::new();
    corpus.entries::<ProRegTx>("proregtx_shared", |raw, item, label| {
      let tx = Transaction::decode(&mut &raw[..]);
      assert!(tx.is_ok(), "{label}");
      if let Ok(tx) = tx {
        txs.push((tx, item.clone()));
      }
    });
    txs
  }

  #[rstest]
  fn shared_collateral_pays_the_template_script() {
    for (tx, item) in shared_transactions() {
      let collateral = &tx.outputs[item.collateral_index as usize];
      assert_eq!(collateral.script_pubkey.as_bytes(), SHARED_COLLATERAL_SCRIPT);
      assert_eq!(tx.check(), None);
    }
  }

  #[rstest]
  #[case::other_script(|tx: &mut Transaction, item: &mut ProRegTx| {
    tx.outputs[item.collateral_index as usize].script_pubkey = ScriptPubKeyBuf::from_bytes(vec![0x51]);
  })]
  #[case::extended_script(|tx: &mut Transaction, item: &mut ProRegTx| {
    let mut script = SHARED_COLLATERAL_SCRIPT.to_vec();
    script.push(0x00);
    tx.outputs[item.collateral_index as usize].script_pubkey = ScriptPubKeyBuf::from_bytes(script);
  })]
  #[case::no_such_output(|tx: &mut Transaction, item: &mut ProRegTx| {
    item.collateral_index = tx.outputs.len() as u32;
  })]
  fn shared_collateral_must_pay_the_template_script(#[case] edit: fn(&mut Transaction, &mut ProRegTx)) {
    for (mut tx, mut item) in shared_transactions() {
      edit(&mut tx, &mut item);
      tx.extra_payload.clear();
      item.encode(&mut tx.extra_payload);
      let error = TxInvalid::PayloadCheck(PayloadInvalid::ProTx(ProTxInvalid::SharesCollateralScript));
      assert_eq!(tx.check(), Some(error));
    }
    assert_eq!(
      ProTxInvalid::SharesCollateralScript.to_string(),
      "bad-protx-shares-collateral-script"
    );
  }

  /// Each join signature recovers, over the consent hash, to the owner of
  /// its share.
  #[rstest]
  fn share_owners_sign_the_consent_hash() {
    for (tx, item) in shared_transactions() {
      let hash = item.consent_hash(&tx);
      for (share, join_sig) in item.shares() {
        assert_eq!(signer(&hash, join_sig.as_bytes()), Some(share.key_id_owner));
      }
    }
  }

  #[rstest]
  #[case::sequence(|tx: &mut Transaction, _: &mut ProRegTx| tx.inputs[0].sequence ^= 1)]
  #[case::output(|tx: &mut Transaction, _: &mut ProRegTx| tx.outputs.truncate(1))]
  #[case::lock_time(|tx: &mut Transaction, _: &mut ProRegTx| tx.lock_time ^= 1)]
  #[case::share(|_: &mut Transaction, item: &mut ProRegTx| item.shares[0].0.amount -= 1)]
  #[case::penalty(|_: &mut Transaction, item: &mut ProRegTx| item.early_penalty += 1)]
  #[case::voting(|_: &mut Transaction, item: &mut ProRegTx| item.key_id_voting = PubKeyHash::default())]
  fn consent_hash_covers(#[case] edit: fn(&mut Transaction, &mut ProRegTx)) {
    for (mut tx, mut item) in shared_transactions() {
      let hash = item.consent_hash(&tx);
      edit(&mut tx, &mut item);
      assert_ne!(item.consent_hash(&tx), hash);
    }
  }

  /// The consent hash leaves out the join signatures and the inputs hash
  /// field, which the transaction inputs already pin.
  #[rstest]
  fn consent_hash_leaves_out_join_signatures() {
    for (tx, mut item) in shared_transactions() {
      let hash = item.consent_hash(&tx);
      for (_, join_sig) in &mut item.shares {
        *join_sig = CompactSignature::from_bytes([0; 65]);
      }
      item.inputs_hash = InputsHash::default();
      assert_eq!(item.consent_hash(&tx), hash);
    }
  }

  /// Address prefixes of mainnet, and of testnet, which regtest shares.
  const MAINNET: AddrParams = AddrParams {
    pubkey_addr: 76,
    script_addr: 16,
    secret_key: 204,
    ext_pubkey: [0x04, 0x88, 0xb2, 0x1e],
    ext_secret: [0x04, 0x88, 0xad, 0xe4],
    bip44_idx: 5,
    platform_hrp: "dash",
  };
  const TESTNET: AddrParams = AddrParams {
    pubkey_addr: 140,
    script_addr: 19,
    secret_key: 239,
    ext_pubkey: [0x04, 0x35, 0x87, 0xcf],
    ext_secret: [0x04, 0x35, 0x83, 0x94],
    bip44_idx: 1,
    platform_hrp: "tdash",
  };

  // A Python script gives each expected string, from the corpus payload
  // fields and the SHA256d of the payload without its signature.
  #[rstest]
  #[case::v2_payout_script(
    "a9e25c9aa56874c5703fc78ce8541364560d5b21eb12812cf452a27776b1f840",
    &MAINNET,
    "XjbaGWaGnvEtuQAUoBgDxJWe8ZNv45upG2|0|XgtGsSKzBvYNoT5UrzyBRxbYoiJ9B6rbDf|XvqUMzeCEhnj9RLYcZSxcQBdTigHj9i1hN|\
     c1527da893c82e0ca6adb83eb8eb45e120d752c2fae594527d5732cd04b50250"
  )]
  #[case::v3_payout_list(
    "ed3eaebc84033d16abe221b0e27a0ba232a89aaeb1331aca6771a72b4ba6db28",
    &TESTNET,
    "yYKjtrDMzAd7E55XofmCvmqpDPAATPQ7tW:7000,yT1Pgoe3uQxYzFtjKBENn6rMp53fccQVk9:3000|2500|\
     yaqN4VVy5XRaSBjDRf6AZW8JTGK2mx274F|ygTMxvJxe4iVW9T88rQ21Xo13DWEtGbyS9|\
     735b98520015f219f0766b8e2a289b8e36af683794080b56fd288b6487dde632"
  )]
  fn sign_string_follows_the_version(#[case] txid: &str, #[case] params: &AddrParams, #[case] expected: &str) {
    let corpus = Corpus::open(env!("CARGO_MANIFEST_DIR"), "proregtx");
    let items = corpus.entries::<ProRegTx>("proregtx", |_, _, _| {});
    assert_eq!(
      items.get(txid).map(|item| item.sign_string(params)).as_deref(),
      Some(expected)
    );
  }

  #[rstest]
  fn sign_string_writes_an_unknown_payout_script_as_hex() {
    let mut item = corpus_item(2, MnType::Regular);
    item.script_payout = ScriptPubKeyBuf::from_bytes(vec![0x51, 0x52]);
    assert!(item.sign_string(&MAINNET).starts_with("5152|"));
  }
}
