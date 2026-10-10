//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! InstantSend locks.

use crate::block::{BlockHash, MAX_DIP0001_BLOCK_SIZE};
use crate::codec_type;
use crate::payload::payload_hash;
use crate::prelude::*;
use crate::transaction::{OutPoint, TxHash};

use dash_num::Hash256;
use dash_pkc::bls::{BlsScIetf, BlsSigBytes};
use dash_types::codec::BaseCodec;
use dash_types::type_id::{TypeId, Unencodable};
use dash_types::{Checkable, CompactSize};

use core::fmt;

/// Most inputs a lock may pin. A transaction input takes at least 41 bytes,
/// so no transaction that fits in a block spends more.
pub const MAX_ISLOCK_INPUTS: usize = MAX_DIP0001_BLOCK_SIZE / 41;

/// Prefix of the lock signing request id.
const LOCK_REQUEST_ID_PREFIX: [u8; 6] = *b"islock";

/// Prefix of the input signing request id.
const INPUT_REQUEST_ID_PREFIX: [u8; 6] = *b"inlock";

/// Quorum signature that locks the inputs of a transaction.
///
/// A lock carries no BLS scheme, so the signature is held as basic. Every
/// network buried v19, which switched quorums to the basic scheme, so only a
/// regtest chain with a deferred v19 height relays legacy locks.
#[derive(Clone, Debug, Eq, Hash, PartialEq, TypeId)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub struct InstantSendLock {
  /// Lock version.
  pub version: u8,
  /// Outpoints the lock pins.
  pub inputs: Vec<OutPoint>,
  /// Hash of the locked transaction.
  pub txid: TxHash,
  /// Hash of the block that starts the signing quorum's cycle.
  pub cycle_hash: BlockHash,
  /// Recovered quorum signature over the txid.
  pub sig: BlsSigBytes<BlsScIetf>,
}

codec_type!(InstantSendLock {
  version,
  inputs,
  txid,
  cycle_hash,
  sig
});

/// InstantSend lock validation failure.
#[derive(Clone, Debug, Eq, Hash, PartialEq, Unencodable)]
pub enum InstantSendLockInvalid {
  /// The txid is null.
  NullTxid,
  /// The lock pins no inputs.
  NoInputs,
  /// The lock pins more than [`MAX_ISLOCK_INPUTS`] inputs.
  TooManyInputs { count: usize },
  /// The lock pins an input twice.
  DuplicateInput { index: usize },
}

impl fmt::Display for InstantSendLockInvalid {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    match self {
      Self::NullTxid => write!(f, "islock txid is null"),
      Self::NoInputs => write!(f, "islock pins no inputs"),
      Self::TooManyInputs { count } => write!(f, "islock pins {count} inputs, more than {MAX_ISLOCK_INPUTS}"),
      Self::DuplicateInput { index } => write!(f, "islock input {index} is a duplicate"),
    }
  }
}

impl Checkable for InstantSendLock {
  type Error = InstantSendLockInvalid;

  fn check(&self) -> Option<Self::Error> {
    if self.txid.is_null() {
      return Some(InstantSendLockInvalid::NullTxid);
    }
    if self.inputs.is_empty() {
      return Some(InstantSendLockInvalid::NoInputs);
    }
    if self.inputs.len() > MAX_ISLOCK_INPUTS {
      return Some(InstantSendLockInvalid::TooManyInputs {
        count: self.inputs.len(),
      });
    }
    let mut seen = BTreeSet::new();
    let index = self.inputs.iter().position(|input| !seen.insert(input))?;
    Some(InstantSendLockInvalid::DuplicateInput { index })
  }
}

impl InstantSendLock {
  /// Quorum signing request id of the lock, which depends on the inputs alone.
  pub fn request_id(&self) -> Hash256 {
    payload_hash(|buf| {
      CompactSize::from(LOCK_REQUEST_ID_PREFIX.len()).encode(buf);
      LOCK_REQUEST_ID_PREFIX.encode(buf);
      self.inputs.encode(buf);
    })
  }

  /// Quorum signing request id of one input, which a masternode signs before
  /// it signs the lock.
  pub fn input_request_id(input: &OutPoint) -> Hash256 {
    payload_hash(|buf| {
      CompactSize::from(INPUT_REQUEST_ID_PREFIX.len()).encode(buf);
      INPUT_REQUEST_ID_PREFIX.encode(buf);
      input.encode(buf);
    })
  }
}

impl fmt::Display for InstantSendLock {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(
      f,
      "InstantSendLock {{ txid: {}, inputs: {} }}",
      self.txid,
      self.inputs.len()
    )
  }
}

#[cfg(test)]
mod tests {
  use super::{InstantSendLock, InstantSendLockInvalid, MAX_ISLOCK_INPUTS};
  use crate::block::BlockHash;
  use crate::prelude::*;
  use crate::transaction::{OutPoint, TxHash};

  use dash_num::Hash256;
  use dash_pkc::bls::BlsSigBytes;
  use dash_types::codec::BaseCodec;
  use dash_types::{Checkable, Numeric};
  use hex_conservative::hex;
  use rstest::rstest;

  fn outpoint(hash_byte: u8, index: u32) -> OutPoint {
    OutPoint {
      hash: TxHash::from_lendian([hash_byte; 32]),
      index,
    }
  }

  fn islock(inputs: Vec<OutPoint>) -> InstantSendLock {
    InstantSendLock {
      version: 1,
      inputs,
      txid: TxHash::from_lendian([0x33; 32]),
      cycle_hash: BlockHash::from_lendian([0x44; 32]),
      sig: BlsSigBytes::from_bytes([0xab; 96]),
    }
  }

  #[rstest]
  fn wire_is_version_inputs_txid_cycle_and_signature() {
    let item = islock(vec![outpoint(0x11, 1)]);
    let mut wire = Vec::new();
    item.encode(&mut wire);
    let mut expected = vec![0x01, 0x01];
    expected.extend([0x11; 32]);
    expected.extend([0x01, 0x00, 0x00, 0x00]);
    expected.extend([0x33; 32]);
    expected.extend([0x44; 32]);
    expected.extend([0xab; 96]);
    assert_eq!(wire, expected);
    assert_eq!(InstantSendLock::decode(&mut wire.as_slice()), Ok(item));
  }

  #[rstest]
  fn request_id_hashes_the_prefix_and_the_inputs() {
    // Python hashlib gives the expected id over `06 "islock"`, the count 2
    // and the outpoints `11..11:1` and `22..22:0`.
    let expected = Hash256::from_lendian(hex!("f8a768e53c7e786d69ca5942977847f0f0bcba6f469c5c588a4d212df93854c4"));
    let mut item = islock(vec![outpoint(0x11, 1), outpoint(0x22, 0)]);
    assert_eq!(item.request_id(), expected);
    item.txid = TxHash::from_lendian([0x55; 32]);
    item.cycle_hash = BlockHash::from_lendian([0x66; 32]);
    assert_eq!(item.request_id(), expected);
    item.inputs.reverse();
    assert_ne!(item.request_id(), expected);
  }

  #[rstest]
  fn input_request_id_hashes_the_prefix_and_the_outpoint() {
    // Python hashlib gives the expected id over `06 "inlock"` and the
    // outpoint `11..11:1`.
    let expected = Hash256::from_lendian(hex!("b773a39c3b51aa2e010a87cf2719a8f595f667e697db8c897c7bf04a4a7114a2"));
    assert_eq!(InstantSendLock::input_request_id(&outpoint(0x11, 1)), expected);
    assert_ne!(InstantSendLock::input_request_id(&outpoint(0x11, 0)), expected);
  }

  #[rstest]
  #[case::one_input(vec![outpoint(0x11, 0)], None)]
  #[case::no_inputs(vec![], Some(InstantSendLockInvalid::NoInputs))]
  #[case::same_hash_other_index(vec![outpoint(0x11, 0), outpoint(0x11, 1)], None)]
  #[case::duplicate(
    vec![outpoint(0x11, 0), outpoint(0x22, 0), outpoint(0x11, 0)],
    Some(InstantSendLockInvalid::DuplicateInput { index: 2 })
  )]
  fn inputs_are_present_and_unique(#[case] inputs: Vec<OutPoint>, #[case] expected: Option<InstantSendLockInvalid>) {
    assert_eq!(islock(inputs).check(), expected);
  }

  #[rstest]
  #[case::at_the_cap(MAX_ISLOCK_INPUTS, None)]
  #[case::past_the_cap(
    MAX_ISLOCK_INPUTS + 1,
    Some(InstantSendLockInvalid::TooManyInputs { count: MAX_ISLOCK_INPUTS + 1 })
  )]
  fn inputs_are_capped_at_48780(#[case] count: usize, #[case] expected: Option<InstantSendLockInvalid>) {
    assert_eq!(MAX_ISLOCK_INPUTS, 48_780);
    let inputs = (0..count).map(|index| outpoint(0x11, index as u32)).collect();
    assert_eq!(islock(inputs).check(), expected);
  }

  #[rstest]
  fn null_txid_fails_first() {
    let mut item = islock(vec![]);
    item.txid = TxHash::from_lendian([0; 32]);
    assert_eq!(item.check(), Some(InstantSendLockInvalid::NullTxid));
  }

  #[cfg(feature = "serde")]
  #[rstest]
  fn serde_round_trips() {
    let item = islock(vec![outpoint(0x11, 1)]);
    assert_eq!(dash_dev::from_json::<InstantSendLock>(&dash_dev::to_json(&item)), item);
  }
}
