//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! AssetLock (type 8): L1 to Platform.

use crate::codec::codec_payload;
use crate::deployment::{Activation, Deployments};
use crate::prelude::*;
use crate::transaction::TxOut;

use dash_script::Recipient;
use dash_types::type_id::{TypeId, Unencodable};
use dash_types::Checkable;

use core::fmt;

/// AssetLock: L1-to-Platform (type 8).
///
/// Version 2 locks are consensus-valid but non-standard, so nodes do not
/// relay them.
#[derive(Clone, Debug, Eq, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub struct AssetLock {
  /// Payload version.
  pub version: u8,
  /// Platform credit allocations.
  pub credit_outputs: Vec<TxOut>,
}

codec_payload!(AssetLock {
  version,
  credit_outputs
});

/// Asset lock validation failure.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Unencodable)]
pub enum AssetLockInvalid {
  /// `bad-assetlocktx-version`
  BadVersion { version: u8 },
  /// `bad-assetlocktx-emptycreditoutputs`
  EmptyCreditOutputs,
  /// `bad-assetlocktx-credit-outofrange`
  CreditOutOfRange { index: usize },
  /// `bad-assetlocktx-pubKeyHash`
  CreditNotP2pkh { index: usize },
  /// `bad-assetlocktx-non-empty-return`
  NonEmptyReturn { index: usize },
  /// `bad-assetlocktx-opreturn-outofrange`
  ReturnOutOfRange { index: usize },
  /// `bad-assetlocktx-multiple-return`
  MultipleReturn { index: usize },
  /// `bad-assetlocktx-no-return`
  NoReturn,
  /// `bad-assetlocktx-creditamount`
  CreditAmountMismatch { credited: u64, returned: u64 },
  /// `bad-assetlocktx-script-pubkey`
  CreditBadScript { index: usize },
  /// `bad-assetlocktx-version-2`
  Version2Inactive { version: u8 },
}

impl core::fmt::Display for AssetLockInvalid {
  fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
    match self {
      Self::BadVersion { version } => write!(f, "bad-assetlocktx-version: {version}"),
      Self::EmptyCreditOutputs => write!(f, "bad-assetlocktx-emptycreditoutputs"),
      Self::CreditOutOfRange { index } => write!(f, "bad-assetlocktx-credit-outofrange: output {index}"),
      Self::CreditNotP2pkh { index } => write!(f, "bad-assetlocktx-pubKeyHash: output {index}"),
      Self::NonEmptyReturn { index } => write!(f, "bad-assetlocktx-non-empty-return: output {index}"),
      Self::ReturnOutOfRange { index } => write!(f, "bad-assetlocktx-opreturn-outofrange: output {index}"),
      Self::MultipleReturn { index } => write!(f, "bad-assetlocktx-multiple-return: output {index}"),
      Self::NoReturn => write!(f, "bad-assetlocktx-no-return"),
      Self::CreditAmountMismatch { credited, returned } => {
        write!(
          f,
          "bad-assetlocktx-creditamount: {credited} credited, {returned} locked"
        )
      }
      Self::CreditBadScript { index } => write!(f, "bad-assetlocktx-script-pubkey: output {index}"),
      Self::Version2Inactive { version } => write!(f, "bad-assetlocktx-version-2: {version}"),
    }
  }
}

impl Checkable for AssetLock {
  type Error = AssetLockInvalid;

  fn check(&self) -> Option<Self::Error> {
    if self.version == 0 || self.version > 2 {
      return Some(AssetLockInvalid::BadVersion { version: self.version });
    }

    if self.credit_outputs.is_empty() {
      return Some(AssetLockInvalid::EmptyCreditOutputs);
    }

    let max_money = bitcoin_units::Amount::MAX_MONEY.to_sat();
    let mut total: u64 = 0;
    for (i, out) in self.credit_outputs.iter().enumerate() {
      let sat = out.value.to_sat();
      if sat == 0 || sat > max_money {
        return Some(AssetLockInvalid::CreditOutOfRange { index: i });
      }
      total = total.saturating_add(sat);
      if total > max_money {
        return Some(AssetLockInvalid::CreditOutOfRange { index: i });
      }
      match (self.version, Recipient::from_script(out.script_pubkey.as_bytes())) {
        (_, Some(Recipient::PubKeyHash(_))) | (2.., Some(Recipient::ScriptHash(_))) => {}
        (2.., _) => return Some(AssetLockInvalid::CreditBadScript { index: i }),
        _ => return Some(AssetLockInvalid::CreditNotP2pkh { index: i }),
      }
    }

    None
  }
}

impl AssetLock {
  /// Rejects a payload version above 1 while v24 is inactive.
  pub fn check_deployments(&self, deployments: Deployments) -> Option<AssetLockInvalid> {
    (deployments.v24 == Activation::Inactive && self.version > 1)
      .then_some(AssetLockInvalid::Version2Inactive { version: self.version })
  }
}

impl fmt::Display for AssetLock {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(
      f,
      "AssetLock {{ v{}, outputs: {} }}",
      self.version,
      self.credit_outputs.len(),
    )
  }
}

#[cfg(all(test, feature = "serde"))]
#[expect(clippy::unwrap_used, reason = "test code")]
mod tests {
  use super::*;

  use bitcoin_primitives::script::ScriptPubKeyBuf;
  use dash_dev::{assert_serde_rt, check_sptx, Corpus};
  use hex_conservative::hex;
  use rstest::rstest;

  #[rstest]
  fn corpus_assetlock() {
    let corpus = Corpus::open(env!("CARGO_MANIFEST_DIR"), "assetlock");
    let items = corpus.entries::<AssetLock>("assetlock", check_sptx);
    assert_serde_rt("assetlock", &items);
  }

  // OP_DUP OP_HASH160, a zero hash160, then OP_EQUALVERIFY OP_CHECKSIG.
  const P2PKH: [u8; 25] = hex!("76a914000000000000000000000000000000000000000088ac");
  // OP_HASH160, a zero hash160, then OP_EQUAL.
  const P2SH: [u8; 23] = hex!("a914000000000000000000000000000000000000000087");
  // A bare OP_TRUE.
  const OP_TRUE: [u8; 1] = hex!("51");

  /// A corpus lock at `version` whose first credit pays `script`.
  fn lock_paying(version: u8, script: &[u8]) -> AssetLock {
    let corpus = Corpus::open(env!("CARGO_MANIFEST_DIR"), "assetlock");
    let mut lock = corpus
      .entries::<AssetLock>("assetlock", |_, _, _| {})
      .into_values()
      .next()
      .unwrap();
    lock.version = version;
    lock.credit_outputs[0].script_pubkey = ScriptPubKeyBuf::from_bytes(script.to_vec());
    lock
  }

  #[rstest]
  #[case::v0(0, Some(AssetLockInvalid::BadVersion { version: 0 }))]
  #[case::v1(1, None)]
  #[case::v2(2, None)]
  #[case::v3(3, Some(AssetLockInvalid::BadVersion { version: 3 }))]
  fn versions_1_and_2_are_known(#[case] version: u8, #[case] expected: Option<AssetLockInvalid>) {
    assert_eq!(lock_paying(version, &P2PKH).check(), expected);
  }

  #[rstest]
  #[case::v1_p2sh(1, &P2SH, Some(AssetLockInvalid::CreditNotP2pkh { index: 0 }))]
  #[case::v1_other(1, &OP_TRUE, Some(AssetLockInvalid::CreditNotP2pkh { index: 0 }))]
  #[case::v2_p2pkh(2, &P2PKH, None)]
  #[case::v2_p2sh(2, &P2SH, None)]
  #[case::v2_other(2, &OP_TRUE, Some(AssetLockInvalid::CreditBadScript { index: 0 }))]
  fn version_2_credits_may_pay_p2sh(
    #[case] version: u8,
    #[case] script: &[u8],
    #[case] expected: Option<AssetLockInvalid>,
  ) {
    assert_eq!(lock_paying(version, script).check(), expected);
  }

  fn deployments(v24: Activation) -> Deployments {
    Deployments {
      v19: Activation::Active,
      v20: Activation::Active,
      v24,
      evo_shares: Activation::Inactive,
    }
  }

  #[rstest]
  #[case::v1_before_v24(1, Activation::Inactive, None)]
  #[case::v2_before_v24(2, Activation::Inactive, Some(AssetLockInvalid::Version2Inactive { version: 2 }))]
  #[case::v1_under_v24(1, Activation::Active, None)]
  #[case::v2_under_v24(2, Activation::Active, None)]
  fn version_2_waits_for_v24(#[case] version: u8, #[case] v24: Activation, #[case] expected: Option<AssetLockInvalid>) {
    let lock = lock_paying(version, &P2PKH);
    assert_eq!(lock.check_deployments(deployments(v24)), expected);
    let reason = AssetLockInvalid::Version2Inactive { version: 2 }.to_string();
    assert_eq!(reason, "bad-assetlocktx-version-2: 2");
  }

  #[rstest]
  fn bad_script_reason() {
    let error = AssetLockInvalid::CreditBadScript { index: 1 };
    assert_eq!(error.to_string(), "bad-assetlocktx-script-pubkey: output 1");
  }
}
