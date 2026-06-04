//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Script opcodes, classification, and address derivation for Dash.

#![no_std]

extern crate alloc;
#[cfg(feature = "std")]
extern crate std;

#[allow(unused_imports, reason = "ergonomic shim, exports may be unused")]
mod prelude;

use crate::opcode::Opcode as Op;
use crate::prelude::*;

use bitcoin_hashes::{hash160, sha256};

pub mod key_id;
pub mod opcode;

pub use key_id::KeyId;
pub use opcode::Opcode;

/// RIPEMD-160(SHA-256) output length in bytes.
const HASH160_LEN: usize = 20;

/// P2PKH scriptPubKey: OP_DUP OP_HASH160 <20> OP_EQUALVERIFY OP_CHECKSIG.
const P2PKH_SCRIPT_LEN: usize = 25;

/// P2SH scriptPubKey: OP_HASH160 <20> OP_EQUAL.
const P2SH_SCRIPT_LEN: usize = 23;

/// P2PK scriptPubKey with a 33-byte compressed public key.
const P2PK_COMPRESSED_SCRIPT_LEN: usize = 35;

/// P2PK scriptPubKey with a 65-byte uncompressed public key.
const P2PK_UNCOMPRESSED_SCRIPT_LEN: usize = 67;

/// SEC1 compressed public key length in bytes.
const P2PK_COMPRESSED_KEY_LEN: usize = 33;

/// SEC1 uncompressed public key length in bytes.
const P2PK_UNCOMPRESSED_KEY_LEN: usize = 65;

/// Known output script patterns.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub enum ScriptKind {
  /// Pay-to-public-key-hash.
  P2pkh,
  /// Pay-to-script-hash.
  P2sh,
  /// Pay-to-public-key.
  P2pk,
  /// Provably unspendable `OP_RETURN`.
  OpReturn,
  /// Unrecognized or unsupported script.
  Unknown,
}

/// Classify a scriptPubKey by its leading pattern.
pub fn classify(script: &[u8]) -> ScriptKind {
  if is_p2pkh(script) {
    return ScriptKind::P2pkh;
  }
  if is_p2sh(script) {
    return ScriptKind::P2sh;
  }
  if is_p2pk(script) {
    return ScriptKind::P2pk;
  }
  if is_op_return(script) {
    return ScriptKind::OpReturn;
  }
  ScriptKind::Unknown
}

/// Returns `true` for P2PKH scripts
/// (`OP_DUP OP_HASH160 <20> OP_EQUALVERIFY OP_CHECKSIG`).
pub fn is_p2pkh(script: &[u8]) -> bool {
  script.len() == P2PKH_SCRIPT_LEN
    && script[0] == Op::Dup.to_u8()
    && script[1] == Op::Hash160.to_u8()
    && script[2] == HASH160_LEN as u8
    && script[23] == Op::EqualVerify.to_u8()
    && script[24] == Op::CheckSig.to_u8()
}

/// Returns `true` for P2SH scripts
/// (`OP_HASH160 <20> OP_EQUAL`).
pub fn is_p2sh(script: &[u8]) -> bool {
  script.len() == P2SH_SCRIPT_LEN
    && script[0] == Op::Hash160.to_u8()
    && script[1] == HASH160_LEN as u8
    && script[22] == Op::Equal.to_u8()
}

/// Returns `true` for P2PK scripts (compressed or uncompressed).
pub fn is_p2pk(script: &[u8]) -> bool {
  let len = script.len();
  (len == P2PK_COMPRESSED_SCRIPT_LEN
    && script[0] == P2PK_COMPRESSED_KEY_LEN as u8
    && script[P2PK_COMPRESSED_SCRIPT_LEN - 1] == Op::CheckSig.to_u8())
    || (len == P2PK_UNCOMPRESSED_SCRIPT_LEN
      && script[0] == P2PK_UNCOMPRESSED_KEY_LEN as u8
      && script[P2PK_UNCOMPRESSED_SCRIPT_LEN - 1] == Op::CheckSig.to_u8())
}

/// Returns `true` when the script starts with `OP_RETURN`.
pub fn is_op_return(script: &[u8]) -> bool {
  script.first() == Some(&Op::Return.to_u8())
}

/// Extracts the 20-byte key hash from a P2PKH script.
pub fn p2pkh_hash160(script: &[u8]) -> Option<&[u8; 20]> {
  if is_p2pkh(script) {
    script[3..23].try_into().ok()
  } else {
    None
  }
}

/// Extracts the 20-byte script hash from a P2SH script.
pub fn p2sh_hash160(script: &[u8]) -> Option<&[u8; 20]> {
  if is_p2sh(script) {
    script[2..22].try_into().ok()
  } else {
    None
  }
}

fn encode_base58_check(prefix: u8, hash: &[u8]) -> Option<String> {
  if hash.len() != HASH160_LEN {
    return None;
  }
  let mut payload = Vec::with_capacity(HASH160_LEN + 1);
  payload.push(prefix);
  payload.extend_from_slice(hash);
  Some(base58ck::encode_check(&payload))
}

/// Encode a 20-byte public-key hash as a Base58Check P2PKH
/// address.
pub fn encode_p2pkh(hash160: &[u8], prefix: u8) -> Option<String> {
  encode_base58_check(prefix, hash160)
}

/// Encode a 20-byte script hash as a Base58Check P2SH address.
pub fn encode_p2sh(hash160: &[u8], prefix: u8) -> Option<String> {
  encode_base58_check(prefix, hash160)
}

/// Encode a `KeyId` as a Base58Check P2PKH address.
pub fn encode_key_id(key_id: &KeyId, prefix: u8) -> String {
  let bytes = key_id.to_bytes();
  let mut payload = Vec::with_capacity(HASH160_LEN + 1);
  payload.push(prefix);
  payload.extend_from_slice(&bytes);
  base58ck::encode_check(&payload)
}

/// Derive a Base58Check address from a scriptPubKey.
///
/// Returns `None` for `OP_RETURN` and unrecognized scripts.
pub fn derive_address(script: &[u8], p2pkh_version: u8, p2sh_version: u8) -> Option<String> {
  match classify(script) {
    ScriptKind::P2pkh => encode_p2pkh(&script[3..23], p2pkh_version),
    ScriptKind::P2sh => encode_p2sh(&script[2..22], p2sh_version),
    ScriptKind::P2pk => {
      let pubkey = if script.len() == P2PK_COMPRESSED_SCRIPT_LEN {
        &script[1..(1 + P2PK_COMPRESSED_KEY_LEN)]
      } else {
        &script[1..(1 + P2PK_UNCOMPRESSED_KEY_LEN)]
      };
      let sha = sha256::Hash::hash(pubkey);
      let h160 = hash160::Hash::from_byte_array(*bitcoin_hashes::ripemd160::Hash::hash(sha.as_ref()).as_byte_array());
      encode_p2pkh(h160.as_ref(), p2pkh_version)
    }
    ScriptKind::OpReturn | ScriptKind::Unknown => None,
  }
}

/// Count legacy signature operations in a script.
///
/// Counts `OP_CHECKSIG`, `OP_CHECKSIGVERIFY`, `OP_CHECKMULTISIG` (weighted by
/// `MAX_PUBKEYS_PER_MULTISIG`), and `OP_CHECKMULTISIGVERIFY`.
pub fn legacy_sigop_count(script: &[u8]) -> usize {
  const MAX_PUBKEYS: usize = 20;

  let mut count: usize = 0;
  let mut i = 0;
  while i < script.len() {
    let byte = script[i];
    if Opcode::is_direct_push(byte) {
      // skip over pushed data
      i += 1 + byte as usize;
      continue;
    }
    let op = Opcode::from_u8(byte);
    match op {
      Op::CheckSig | Op::CheckSigVerify => count += 1,
      Op::CheckMultiSig | Op::CheckMultiSigVerify => {
        count += MAX_PUBKEYS;
      }
      Op::PushData1 if i + 1 < script.len() => {
        i += 2 + script[i + 1] as usize;
        continue;
      }
      Op::PushData2 if i + 2 < script.len() => {
        let n = u16::from_le_bytes([script[i + 1], script[i + 2]]);
        i += 3 + n as usize;
        continue;
      }
      Op::PushData4 if i + 4 < script.len() => {
        let n = u32::from_le_bytes([script[i + 1], script[i + 2], script[i + 3], script[i + 4]]);
        i += 5 + n as usize;
        continue;
      }
      _ => {}
    }
    i += 1;
  }
  count
}

#[cfg(test)]
mod tests {
  use super::*;

  use hex_literal::hex;

  #[test]
  fn p2pkh_valid() {
    let script = hex!("76a914000000000000000000000000000000000000000088ac");
    assert!(is_p2pkh(&script));
    assert_eq!(classify(&script), ScriptKind::P2pkh);
  }

  #[test]
  fn p2pkh_extra_byte_is_not_p2pkh() {
    let script = hex!("76a914000000000000000000000000000000000000000088acac");
    assert!(!is_p2pkh(&script));
  }

  #[test]
  fn p2sh_is_not_p2pkh() {
    let script = hex!("a914000000000000000000000000000000000000000087");
    assert!(!is_p2pkh(&script));
  }

  #[test]
  fn p2pkh_missing_leading_opcodes() {
    let script = hex!("a91400000000000000000000000000000000000000008888ac6a");
    assert!(!is_p2pkh(&script));
  }

  #[test]
  fn p2pkh_truncated_hash() {
    let script = hex!("76a9140000000088ac");
    assert!(!is_p2pkh(&script));
  }

  #[test]
  fn p2pkh_missing_trailing_opcodes() {
    let script = hex!("76a91400000000000000000000000000000000000000001414");
    assert!(!is_p2pkh(&script));
  }

  #[test]
  fn p2sh_valid() {
    let script = hex!("a914000000000000000000000000000000000000000087");
    assert!(is_p2sh(&script));
    assert_eq!(classify(&script), ScriptKind::P2sh);
  }

  #[test]
  fn p2sh_pushdata1_is_not_p2sh() {
    // direct push byte required; PUSHDATA1 must not match
    let script = hex!("a94c14000000000000000000000000000000000000000087");
    assert!(!is_p2sh(&script));
  }

  #[test]
  fn p2sh_empty_is_not_p2sh() {
    assert!(!is_p2sh(&[]));
  }

  #[test]
  fn p2sh_wrong_leading_opcode() {
    let script = hex!("611400000000000000000000000000000000000000000087");
    assert!(!is_p2sh(&script));
  }

  #[test]
  fn p2sh_wrong_trailing_opcode() {
    let script = hex!("a9140000000000000000000000000000000000000000ac");
    assert!(!is_p2sh(&script));
  }

  #[test]
  fn p2pk_compressed_even() {
    let script = hex!("2102 00000000000000000000000000000000 00000000000000000000000000000000 ac");
    assert_eq!(script.len(), 35);
    assert!(is_p2pk(&script));
    assert_eq!(classify(&script), ScriptKind::P2pk);
  }

  #[test]
  fn p2pk_compressed_odd() {
    let script = hex!("2103 00000000000000000000000000000000 00000000000000000000000000000000 ac");
    assert!(is_p2pk(&script));
  }

  #[test]
  fn p2pk_uncompressed() {
    let script = hex!(
      "4104 00000000000000000000000000000000 00000000000000000000000000000000"
      "     00000000000000000000000000000000 00000000000000000000000000000000 ac"
    );
    assert_eq!(script.len(), 67);
    assert!(is_p2pk(&script));
  }

  #[test]
  fn p2pk_missing_checksig() {
    // truncated: no trailing OP_CHECKSIG
    let script = hex!("2102 00000000000000000000000000000000 00000000000000000000000000000000");
    assert!(!is_p2pk(&script));
  }

  #[test]
  fn p2pk_wrong_trailing_opcode() {
    // OP_EQUALVERIFY (0x88) in place of OP_CHECKSIG
    let script = hex!("2102 00000000000000000000000000000000 00000000000000000000000000000000 88");
    assert!(!is_p2pk(&script));
  }

  #[test]
  fn p2pk_too_short() {
    let script = hex!("210200ac");
    assert!(!is_p2pk(&script));
  }

  #[test]
  fn op_return_with_data() {
    let script = hex!("6a04deadbeef");
    assert!(is_op_return(&script));
    assert_eq!(classify(&script), ScriptKind::OpReturn);
  }

  #[test]
  fn op_return_bare() {
    assert!(is_op_return(&[Op::Return.to_u8()]));
  }

  #[test]
  fn op_return_empty_is_not_op_return() {
    assert!(!is_op_return(&[]));
  }

  #[test]
  fn empty_is_unknown() {
    assert_eq!(classify(&[]), ScriptKind::Unknown);
  }

  #[test]
  fn arithmetic_script_is_unknown() {
    let script = hex!("59935b87");
    assert_eq!(classify(&script), ScriptKind::Unknown);
  }

  #[test]
  fn p2pkh_hash160_extraction() {
    let script = hex!("76a914 0102030405060708091011121314151617181920 88ac");
    assert_eq!(script.len(), 25);
    assert!(is_p2pkh(&script));
    let hash = p2pkh_hash160(&script);
    assert_eq!(hash, Some(&hex!("0102030405060708091011121314151617181920")));
  }

  #[test]
  fn p2sh_hash160_extraction() {
    let script = hex!("a914aabbccddee00112233445566778899aabbccddee87");
    assert!(is_p2sh(&script));
    let hash = p2sh_hash160(&script);
    assert_eq!(hash, Some(&hex!("aabbccddee00112233445566778899aabbccddee")));
  }

  #[test]
  fn hash_extraction_returns_none_for_wrong_type() {
    let p2sh = hex!("a914000000000000000000000000000000000000000087");
    assert_eq!(p2pkh_hash160(&p2sh), None);

    let p2pkh = hex!("76a914000000000000000000000000000000000000000088ac");
    assert_eq!(p2sh_hash160(&p2pkh), None);
  }

  #[test]
  fn derive_p2sh_address() {
    let script = hex!("a914242424242424242424242424242424242424242487");
    assert_eq!(
      derive_address(&script, 76, 16),
      Some("7VhkNn2LJ9YE35ZGbWkfPjKisrCFT7ovqy".to_owned())
    );
  }

  #[test]
  fn encode_p2pkh_rejects_wrong_length() {
    assert_eq!(encode_p2pkh(&[0x42; 19], 76), None);
  }

  #[test]
  fn op_return_address_is_none() {
    let script = hex!("6a00");
    assert_eq!(derive_address(&script, 76, 16), None);
  }

  #[test]
  fn unknown_script_address_is_none() {
    assert_eq!(derive_address(&[], 76, 16), None);
  }

  #[test]
  fn sigop_empty_script() {
    assert_eq!(legacy_sigop_count(&[]), 0);
  }

  #[test]
  fn sigop_single_checksig() {
    let script = [Op::CheckSig.to_u8()];
    assert_eq!(legacy_sigop_count(&script), 1);
  }

  #[test]
  fn sigop_single_checksigverify() {
    let script = [Op::CheckSigVerify.to_u8()];
    assert_eq!(legacy_sigop_count(&script), 1);
  }

  #[test]
  fn sigop_checkmultisig_counts_as_20() {
    let script = [Op::CheckMultiSig.to_u8()];
    assert_eq!(legacy_sigop_count(&script), 20);
  }

  #[test]
  fn sigop_checkmultisigverify_counts_as_20() {
    let script = [Op::CheckMultiSigVerify.to_u8()];
    assert_eq!(legacy_sigop_count(&script), 20);
  }

  #[test]
  fn sigop_p2pkh_script() {
    // P2PKH has one OP_CHECKSIG
    let script = hex!("76a914000000000000000000000000000000000000000088ac");
    assert_eq!(legacy_sigop_count(&script), 1);
  }

  #[test]
  fn sigop_multisig_then_checksig() {
    // legacy count: CHECKMULTISIG(20) + CHECKSIG(1) = 21
    let script = hex!(
      "51"
      "1400000000000000000000000000000000000000001400000000000000000000000000000000000000"
      "52ae"
      "63ac68"
    );
    assert_eq!(legacy_sigop_count(&script), 21);
  }

  #[test]
  fn sigop_skips_pushed_data() {
    // 0xac inside pushed data must not count as OP_CHECKSIG
    let script = hex!("02acac");
    assert_eq!(legacy_sigop_count(&script), 0);
  }

  #[test]
  fn sigop_skips_pushdata1() {
    // 0xac inside PUSHDATA1 payload must not count
    let script = hex!("4c01ac");
    assert_eq!(legacy_sigop_count(&script), 0);
  }

  #[test]
  fn sigop_skips_pushdata2() {
    // 0xac inside PUSHDATA2 payload must not count
    let script = hex!("4d0100ac");
    assert_eq!(legacy_sigop_count(&script), 0);
  }

  #[test]
  fn sigop_skips_pushdata4() {
    // 0xac inside PUSHDATA4 payload must not count
    let script = hex!("4e01000000ac");
    assert_eq!(legacy_sigop_count(&script), 0);
  }
}
