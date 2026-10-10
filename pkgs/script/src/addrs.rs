//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Address definitions and network parameters.

use crate::prelude::*;
use crate::{opcode::Opcode, PubKeyHash, ScriptHash};

use base58ck::decode_check;
use bech32::primitives::decode::UncheckedHrpstring;
use bech32::{Bech32, Bech32m, Hrp};
use dash_num::Hash160;
use dash_pkc::ecdsa::EcdsaPkBytes;
use dash_types::codec::{BaseCodec, EncodeBuf};
use dash_types::{type_cvrt, type_id::Unencodable, Hashable, Numeric};

use core::fmt;

/// Network address encoding parameters.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Unencodable)]
pub struct AddrParams {
  /// P2PKH address version byte.
  pub pubkey_addr: u8,
  /// P2SH address version byte.
  pub script_addr: u8,
  /// WIF private key version byte.
  pub secret_key: u8,
  /// BIP32 extended public key prefix.
  pub ext_pubkey: [u8; 4],
  /// BIP32 extended secret key prefix.
  pub ext_secret: [u8; 4],
  /// BIP44 coin type index.
  pub bip44_idx: u32,
  /// Bech32m human-readable part of DIP-18 Platform addresses.
  pub platform_hrp: &'static str,
}

/// DIP-18 type byte of a Platform P2PKH address.
const PLATFORM_P2PKH: u8 = 0xb0;

/// DIP-18 type byte of a Platform P2SH address.
const PLATFORM_P2SH: u8 = 0x80;

/// Bytes a Platform address carries, the type byte and a HASH160.
const PLATFORM_PAYLOAD_LEN: usize = 1 + Hash160::LEN;

/// Longest string a bech32 decoder accepts.
const BECH32_MAX_LEN: usize = 90;

/// DIP-18 Platform address decoding failure.
#[derive(Clone, Debug, Eq, Hash, PartialEq, Unencodable)]
pub enum PlatformAddrError {
  /// The string is not valid bech32 or bech32m.
  InvalidEncoding,
  /// The checksum is bech32 rather than bech32m.
  NotBech32m,
  /// The human-readable part belongs to another network.
  WrongHrp,
  /// The 5-bit groups leave more than 4 bits, or non-zero padding.
  BadPadding,
  /// The payload is not a type byte and a HASH160.
  BadLength { len: usize },
  /// The type byte is neither P2PKH nor P2SH.
  UnknownType { type_byte: u8 },
}

impl fmt::Display for PlatformAddrError {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    match self {
      Self::InvalidEncoding => write!(f, "invalid bech32m encoding"),
      Self::NotBech32m => write!(f, "platform addresses require a bech32m checksum"),
      Self::WrongHrp => write!(f, "invalid platform hrp for the network"),
      Self::BadPadding => write!(f, "invalid platform address payload encoding"),
      Self::BadLength { len } => write!(f, "invalid platform address payload length: {len}"),
      Self::UnknownType { type_byte } => write!(f, "unknown dip-18 type byte: {type_byte:#04x}"),
    }
  }
}

#[cfg(feature = "std")]
impl std::error::Error for PlatformAddrError {}

/// Recipient parsed from address.
#[derive(Clone, Debug, Eq, Hash, PartialEq, Unencodable)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(tag = "type", content = "data"))]
pub enum Recipient {
  /// Pay-to-public-key.
  #[cfg_attr(feature = "serde", serde(rename = "p2pk"))]
  PubKey(EcdsaPkBytes),
  /// Pay-to-public-key-hash.
  #[cfg_attr(feature = "serde", serde(rename = "p2pkh"))]
  PubKeyHash(PubKeyHash),
  /// Pay-to-script-hash.
  #[cfg_attr(feature = "serde", serde(rename = "p2sh"))]
  ScriptHash(ScriptHash),
  /// Provably unspendable `OP_RETURN`.
  #[cfg_attr(feature = "serde", serde(rename = "unspendable"))]
  Unspendable,
}

impl Recipient {
  /// Parse a scriptPubKey. Returns `None` for unrecognized patterns.
  pub fn from_script(script: &[u8]) -> Option<Self> {
    let len = script.len();

    // P2PKH: OP_DUP OP_HASH160 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG
    if len == 25
      && script[0] == Opcode::Dup.to_base()
      && script[1] == Opcode::Hash160.to_base()
      && script[2] == Hash160::LEN as u8
      && script[23] == Opcode::EqualVerify.to_base()
      && script[24] == Opcode::CheckSig.to_base()
    {
      let bytes: &[u8; Hash160::LEN] = script[3..23].try_into().ok()?;
      return Some(Self::PubKeyHash(PubKeyHash::from(*bytes)));
    }

    // P2SH: OP_HASH160 <20 bytes> OP_EQUAL
    if len == 23
      && script[0] == Opcode::Hash160.to_base()
      && script[1] == Hash160::LEN as u8
      && script[22] == Opcode::Equal.to_base()
    {
      let bytes: &[u8; Hash160::LEN] = script[2..22].try_into().ok()?;
      return Some(Self::ScriptHash(ScriptHash::from(*bytes)));
    }

    // P2PK: <33 or 65 byte pubkey> OP_CHECKSIG
    if (len == 35 || len == 67) && script[0] as usize == len - 2 && script[len - 1] == Opcode::CheckSig.to_base() {
      let pk = EcdsaPkBytes::from_bytes(&script[1..len - 1])?;
      return Some(Self::PubKey(pk));
    }

    // OP_RETURN
    if script.first() == Some(&Opcode::Return.to_base()) {
      return Some(Self::Unspendable);
    }

    None
  }

  /// Encode as a Base58Check address.
  ///
  /// Returns `None` for `Unspendable`, which has no address form.
  pub fn to_base58c(&self, params: &AddrParams) -> Option<String> {
    match self {
      Self::PubKeyHash(h) => Some(h.to_base58c(params.pubkey_addr)),
      Self::ScriptHash(h) => Some(h.to_base58c(params.script_addr)),
      Self::PubKey(pk) => Some(pk.hash().to_base58c(params.pubkey_addr)),
      Self::Unspendable => None,
    }
  }

  /// Decode a Base58Check address string.
  ///
  /// Returns `None` when the string is not a valid P2PKH or P2SH address for
  /// the given network parameters.
  pub fn from_base58c(s: &str, params: &AddrParams) -> Option<Self> {
    let data = decode_check(s).ok()?;
    if data.len() != 21 {
      return None;
    }
    let hash: [u8; Hash160::LEN] = data[1..].try_into().ok()?;
    if data[0] == params.pubkey_addr {
      Some(Self::PubKeyHash(PubKeyHash::from(hash)))
    } else if data[0] == params.script_addr {
      Some(Self::ScriptHash(ScriptHash::from(hash)))
    } else {
      None
    }
  }

  /// Encode as a DIP-18 Platform address.
  ///
  /// Returns `None` for `Unspendable`, which has no address form.
  pub fn to_platform(&self, params: &AddrParams) -> Option<String> {
    let (type_byte, hash) = match self {
      Self::PubKeyHash(h) => (PLATFORM_P2PKH, *h.as_bytes()),
      Self::ScriptHash(h) => (PLATFORM_P2SH, *h.as_bytes()),
      Self::PubKey(pk) => (PLATFORM_P2PKH, *pk.hash().as_bytes()),
      Self::Unspendable => return None,
    };
    let mut payload = [0; PLATFORM_PAYLOAD_LEN];
    payload[0] = type_byte;
    payload[1..].copy_from_slice(&hash);
    let hrp = Hrp::parse(params.platform_hrp).ok()?;
    bech32::encode_lower::<Bech32m>(hrp, &payload).ok()
  }

  /// Decode a DIP-18 Platform address of the network `params` describes.
  ///
  /// # Errors
  ///
  /// Returns the first [`PlatformAddrError`] the string meets, in the order
  /// the variants are declared.
  pub fn from_platform(s: &str, params: &AddrParams) -> Result<Self, PlatformAddrError> {
    if s.len() > BECH32_MAX_LEN {
      return Err(PlatformAddrError::InvalidEncoding);
    }
    let unchecked = UncheckedHrpstring::new(s).map_err(|_| PlatformAddrError::InvalidEncoding)?;
    if !unchecked.has_valid_checksum::<Bech32m>() {
      return Err(if unchecked.has_valid_checksum::<Bech32>() {
        PlatformAddrError::NotBech32m
      } else {
        PlatformAddrError::InvalidEncoding
      });
    }
    if !unchecked.hrp().lowercase_char_iter().eq(params.platform_hrp.chars()) {
      return Err(PlatformAddrError::WrongHrp);
    }

    let checked = unchecked.remove_checksum::<Bech32m>();
    let payload = regroup_5_to_8(checked.fe32_iter::<core::iter::Empty<u8>>().map(bech32::Fe32::to_u8))?;
    let bad_length = PlatformAddrError::BadLength { len: payload.len() };
    let Some((&type_byte, rest)) = payload.split_first() else {
      return Err(bad_length);
    };
    let Ok(hash) = <[u8; Hash160::LEN]>::try_from(rest) else {
      return Err(bad_length);
    };
    match type_byte {
      PLATFORM_P2PKH => Ok(Self::PubKeyHash(PubKeyHash::from(hash))),
      PLATFORM_P2SH => Ok(Self::ScriptHash(ScriptHash::from(hash))),
      type_byte => Err(PlatformAddrError::UnknownType { type_byte }),
    }
  }

  /// Encode as a scriptPubKey.
  pub fn to_script(&self, buf: &mut impl EncodeBuf) {
    match self {
      Self::PubKeyHash(h) => {
        buf.push(Opcode::Dup.to_base());
        buf.push(Opcode::Hash160.to_base());
        buf.push(Hash160::LEN as u8);
        h.encode(buf);
        buf.push(Opcode::EqualVerify.to_base());
        buf.push(Opcode::CheckSig.to_base());
      }
      Self::ScriptHash(h) => {
        buf.push(Opcode::Hash160.to_base());
        buf.push(Hash160::LEN as u8);
        h.encode(buf);
        buf.push(Opcode::Equal.to_base());
      }
      Self::PubKey(pk) => {
        let bytes = pk.as_bytes();
        buf.push(bytes.len() as u8);
        // nosemgrep: codec-no-raw-extend
        buf.extend_from_slice(bytes);
        buf.push(Opcode::CheckSig.to_base());
      }
      Self::Unspendable => {
        buf.push(Opcode::Return.to_base());
      }
    }
  }
}

/// Regroups 5-bit values into bytes, refusing more than 4 leftover bits and
/// non-zero padding.
fn regroup_5_to_8(values: impl Iterator<Item = u8>) -> Result<Vec<u8>, PlatformAddrError> {
  let mut bytes = Vec::new();
  let (mut acc, mut bits) = (0u32, 0u32);
  for value in values {
    acc = ((acc << 5) | u32::from(value)) & 0xfff;
    bits += 5;
    if bits >= 8 {
      bits -= 8;
      bytes.push((acc >> bits) as u8);
    }
  }
  if bits >= 5 || (acc << (8 - bits)) & 0xff != 0 {
    return Err(PlatformAddrError::BadPadding);
  }
  Ok(bytes)
}

type_cvrt!(
  enum Recipient {
    PubKey(EcdsaPkBytes),
    PubKeyHash(PubKeyHash),
    ScriptHash(ScriptHash),
  }
);

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "test code")]
mod tests {
  use super::*;

  use bech32::{ByteIterExt, Fe32IterExt};
  use hex_conservative::hex;
  use rstest::rstest;

  const MAINNET: AddrParams = AddrParams {
    pubkey_addr: 76,
    script_addr: 16,
    secret_key: 204,
    ext_pubkey: [0x04, 0x88, 0xB2, 0x1E],
    ext_secret: [0x04, 0x88, 0xAD, 0xE4],
    bip44_idx: 5,
    platform_hrp: "dash",
  };

  // The generator point's coordinates shared across P2PK vectors
  macro_rules! gen_x {
    () => {
      "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
    };
  }
  macro_rules! gen_y {
    () => {
      "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"
    };
  }

  // OP_DUP OP_HASH160, a zero hash160, then OP_EQUALVERIFY OP_CHECKSIG.
  const P2PKH: [u8; 25] = hex!(concat!("76a914", "0000000000000000000000000000000000000000", "88ac"));
  // OP_HASH160, the same zero hash160, then OP_EQUAL.
  const P2SH: [u8; 23] = hex!(concat!("a914", "0000000000000000000000000000000000000000", "87"));
  // The generator is used so the vectors are real keys.
  const P2PK_COMP_EVEN: [u8; 35] = hex!(concat!("21", "02", gen_x!(), "ac"));
  // Same X, 0x03 header: the other root, i.e. the negated generator, Y odd.
  const P2PK_COMP_ODD: [u8; 35] = hex!(concat!("21", "03", gen_x!(), "ac"));
  // The generator again, both coordinates spelled out.
  const P2PK_UNCOMP: [u8; 67] = hex!(concat!("41", "04", gen_x!(), gen_y!(), "ac"));
  // X = 0 has no point on the curve, but the SEC1 framing is well-formed, so
  // a structural classifier still reads it as P2PK.
  const P2PK_X_ZERO: [u8; 35] = hex!(concat!(
    "21",
    "02",
    "0000000000000000000000000000000000000000000000000000000000000000",
    "ac",
  ));
  // The generator's X with a Y that is not its square root: likewise well-formed,
  // just as unspendable.
  const P2PK_BAD_Y: [u8; 67] = hex!(concat!(
    "41",
    "04",
    gen_x!(),
    "0000000000000000000000000000000000000000000000000000000000000001",
    "ac",
  ));

  #[rstest]
  #[case::p2pkh(&P2PKH, Recipient::PubKeyHash(PubKeyHash::from([0; Hash160::LEN])))]
  #[case::p2sh(&P2SH, Recipient::ScriptHash(ScriptHash::from([0; Hash160::LEN])))]
  #[case::p2pkh_nonzero(
    &hex!("76a914010203040506070809101112131415161718192088ac"),
    Recipient::PubKeyHash(PubKeyHash::from(hex!("0102030405060708091011121314151617181920"))),
  )]
  #[case::p2sh_nonzero(
    &hex!("a914aabbccddee00112233445566778899aabbccddee87"),
    Recipient::ScriptHash(ScriptHash::from(hex!("aabbccddee00112233445566778899aabbccddee"))),
  )]
  #[case::op_return_data(&hex!("6a04deadbeef"), Recipient::Unspendable)]
  #[case::op_return_bare(&[Opcode::Return.to_base()], Recipient::Unspendable)]
  fn from_script_matches(#[case] script: &[u8], #[case] expected: Recipient) {
    assert_eq!(Recipient::from_script(script), Some(expected));
  }

  #[rstest]
  #[case::p2pk_even(&P2PK_COMP_EVEN, &P2PK_COMP_EVEN[1..34])]
  #[case::p2pk_odd(&P2PK_COMP_ODD, &P2PK_COMP_ODD[1..34])]
  #[case::p2pk_uncomp(&P2PK_UNCOMP, &P2PK_UNCOMP[1..66])]
  #[case::p2pk_x_not_on_curve(&P2PK_X_ZERO, &P2PK_X_ZERO[1..34])]
  #[case::p2pk_y_not_a_root(&P2PK_BAD_Y, &P2PK_BAD_Y[1..66])]
  fn from_script_p2pk(#[case] script: &[u8], #[case] key_bytes: &[u8]) {
    assert!(matches!(
      Recipient::from_script(script),
      Some(Recipient::PubKey(pk)) if pk.as_bytes() == key_bytes
    ));
  }

  #[rstest]
  #[case::empty(&[])]
  #[case::p2pkh_extra_byte(&hex!("76a914000000000000000000000000000000000000000088acac"))]
  #[case::p2pkh_truncated(&hex!("76a9140000000088ac"))]
  #[case::p2pkh_wrong_trailing(&hex!("76a91400000000000000000000000000000000000000001414"))]
  #[case::p2pkh_wrong_leading(&hex!("a91400000000000000000000000000000000000000008888ac6a"))]
  #[case::p2sh_pushdata1(&hex!("a94c14000000000000000000000000000000000000000087"))]
  #[case::p2sh_wrong_leading(&hex!("611400000000000000000000000000000000000000000087"))]
  #[case::p2sh_wrong_trailing(&hex!("a9140000000000000000000000000000000000000000ac"))]
  #[case::p2pk_missing_checksig(&hex!(
    "21020000000000000000000000000000000000000000000000000000000000000000"
  ))]
  #[case::p2pk_wrong_trailing(&hex!(
    "2102000000000000000000000000000000000000000000000000000000000000000088"
  ))]
  #[case::p2pk_too_short(&hex!("210200ac"))]
  #[case::arithmetic(&hex!("59935b87"))]
  #[case::p2sh_pushdata2(&hex!("4d1400000000000000000000000000000000000000000087"))]
  #[case::p2sh_pushdata4(&hex!("4e14000000000000000000000000000000000000000000000087"))]
  fn from_script_rejects(#[case] script: &[u8]) {
    assert!(Recipient::from_script(script).is_none());
  }

  #[rstest]
  #[case::p2pk(&P2PK_COMP_EVEN, Some("XmN7PQYWKn5MJFna5fRYgP6mxT2F7xpekE"))]
  #[case::p2pkh(&P2PKH, Some("XagqqFetxiDb9wbartKDrXgnqLah6SqX2S"))]
  #[case::p2sh(
    &hex!("a914242424242424242424242424242424242424242487"),
    Some("7VhkNn2LJ9YE35ZGbWkfPjKisrCFT7ovqy"),
  )]
  #[case::op_return(&hex!("6a00"), None)]
  fn to_base58c_address(#[case] script: &[u8], #[case] expected: Option<&str>) {
    let addr = Recipient::from_script(script).and_then(|r| r.to_base58c(&MAINNET));
    assert_eq!(addr.as_deref(), expected);
  }

  // `Unspendable` is deliberately excluded: it discards the OP_RETURN operand,
  // so it is the one variant that cannot round-trip.
  #[rstest]
  #[case::p2pkh(&P2PKH)]
  #[case::p2sh(&P2SH)]
  #[case::p2pk_even(&P2PK_COMP_EVEN)]
  #[case::p2pk_odd(&P2PK_COMP_ODD)]
  #[case::p2pk_uncomp(&P2PK_UNCOMP)]
  fn to_script_round_trips(#[case] script: &[u8]) {
    let recipient = Recipient::from_script(script).unwrap();
    let mut buf = Vec::new();
    recipient.to_script(&mut buf);
    assert_eq!(buf.as_slice(), script);
  }

  #[rstest]
  fn unspendable_to_script_drops_operand() {
    let recipient = Recipient::from_script(&hex!("6a04deadbeef")).unwrap();
    let mut buf = Vec::new();
    recipient.to_script(&mut buf);
    assert_eq!(buf.as_slice(), &[Opcode::Return.to_base()]);
  }

  #[rstest]
  #[case::p2pkh("XdywTHuctyLo75vU4gjnVFeve7erBRcpzP", Recipient::PubKeyHash(PubKeyHash::from([0x24; Hash160::LEN])))]
  #[case::p2sh("7VhkNn2LJ9YE35ZGbWkfPjKisrCFT7ovqy", Recipient::ScriptHash(ScriptHash::from([0x24; Hash160::LEN])))]
  fn from_base58c_round_trips(#[case] addr: &str, #[case] expected: Recipient) {
    let recipient = Recipient::from_base58c(addr, &MAINNET).unwrap();
    assert_eq!(recipient, expected);
    assert_eq!(recipient.to_base58c(&MAINNET).as_deref(), Some(addr));
  }

  #[rstest]
  // Valid Base58Check, but the testnet version byte matches no MAINNET kind.
  #[case::wrong_version("yPcYUEz4LWzsSpr1dY4BXH5GvQ9DdCV6cv")]
  #[case::bad_checksum("7VhkNn2LJ9YE35ZGbWkfPjKisrCFT7ovqz")]
  #[case::not_base58("not an address")]
  #[case::empty("")]
  fn from_base58c_rejects(#[case] addr: &str) {
    assert!(Recipient::from_base58c(addr, &MAINNET).is_none());
  }

  const TESTNET: AddrParams = AddrParams {
    pubkey_addr: 140,
    script_addr: 19,
    secret_key: 239,
    ext_pubkey: [0x04, 0x35, 0x87, 0xCF],
    ext_secret: [0x04, 0x35, 0x83, 0x94],
    bip44_idx: 1,
    platform_hrp: "tdash",
  };

  // DIP-0018 test vectors, as the reference's key_io_tests.cpp lists them.
  #[rstest]
  #[case(MAINNET, false, hex!("f7da0a2b5cbd4ff6bb2c4d89b67d2f3ffeec0525"), "dash1krma5z3ttj75la4m93xcndna9ullamq9y5e9n5rs")]
  #[case(MAINNET, false, hex!("a5ff0046217fd1c7d238e3e146cc5bfd90832a7e"), "dash1kzjl7qzxy9lar37j8r37z3kvt07epqe20ckxfezw")]
  #[case(MAINNET, false, hex!("6d92674fd64472a3dfcfc3ebcfed7382bf699d7b"), "dash1kpkeye606ez89g7lelp7hnldwwpt76va0v3j6x28")]
  #[case(TESTNET, false, hex!("f7da0a2b5cbd4ff6bb2c4d89b67d2f3ffeec0525"), "tdash1krma5z3ttj75la4m93xcndna9ullamq9y5fzq2j7")]
  #[case(TESTNET, false, hex!("a5ff0046217fd1c7d238e3e146cc5bfd90832a7e"), "tdash1kzjl7qzxy9lar37j8r37z3kvt07epqe20cxp68nq")]
  #[case(TESTNET, false, hex!("6d92674fd64472a3dfcfc3ebcfed7382bf699d7b"), "tdash1kpkeye606ez89g7lelp7hnldwwpt76va0vp4fcmf")]
  #[case(MAINNET, true, hex!("43fa183cf3fb6e9e7dc62b692aeb4fc8d8045636"), "dash1sppl5xpu70aka8nacc4kj2htflydspzkxch4cad6")]
  #[case(TESTNET, true, hex!("43fa183cf3fb6e9e7dc62b692aeb4fc8d8045636"), "tdash1sppl5xpu70aka8nacc4kj2htflydspzkxc8jtru5")]
  fn platform_vectors_round_trip(
    #[case] params: AddrParams,
    #[case] is_p2sh: bool,
    #[case] hash: [u8; 20],
    #[case] addr: &str,
  ) {
    let expected = if is_p2sh {
      Recipient::ScriptHash(ScriptHash::from(hash))
    } else {
      Recipient::PubKeyHash(PubKeyHash::from(hash))
    };
    assert_eq!(Recipient::from_platform(addr, &params), Ok(expected.clone()));
    assert_eq!(expected.to_platform(&params).as_deref(), Some(addr));
    // A single-case string decodes in either case.
    assert_eq!(Recipient::from_platform(&addr.to_uppercase(), &params), Ok(expected));
  }

  #[rstest]
  fn platform_encoding_skips_unspendable() {
    assert_eq!(Recipient::Unspendable.to_platform(&MAINNET), None);
  }

  /// Bech32m string of `hrp` over the 5-bit groups of `values`.
  fn bech32m_of_groups(hrp: &str, values: &[u8]) -> String {
    let hrp = Hrp::parse(hrp).unwrap();
    values
      .iter()
      .map(|&value| bech32::Fe32::try_from(value).unwrap())
      .with_checksum::<Bech32m>(&hrp)
      .chars()
      .collect()
  }

  /// 5-bit groups of `bytes`, zero-padded.
  fn groups_of(bytes: &[u8]) -> Vec<u8> {
    bytes.iter().copied().bytes_to_fes().map(bech32::Fe32::to_u8).collect()
  }

  const P2PKH_PAYLOAD: [u8; 21] = hex!("b0f7da0a2b5cbd4ff6bb2c4d89b67d2f3ffeec0525");

  #[rstest]
  #[case::empty(String::new(), PlatformAddrError::InvalidEncoding)]
  #[case::garbage(String::from("not-an-address"), PlatformAddrError::InvalidEncoding)]
  #[case::mixed_case(
    String::from("Dash1krma5z3ttj75la4m93xcndna9ullamq9y5e9n5rs"),
    PlatformAddrError::InvalidEncoding
  )]
  #[case::bad_checksum(
    String::from("dash1krma5z3ttj75la4m93xcndna9ullamq9y5e9n5rq"),
    PlatformAddrError::InvalidEncoding
  )]
  #[case::bech32_checksum(
    bech32::encode_lower::<Bech32>(Hrp::parse("dash").unwrap(), &P2PKH_PAYLOAD).unwrap(),
    PlatformAddrError::NotBech32m
  )]
  #[case::other_network(
    String::from("tdash1krma5z3ttj75la4m93xcndna9ullamq9y5fzq2j7"),
    PlatformAddrError::WrongHrp
  )]
  #[case::non_zero_padding(
    {
      let mut groups = groups_of(&P2PKH_PAYLOAD);
      *groups.last_mut().unwrap() |= 1;
      bech32m_of_groups("dash", &groups)
    },
    PlatformAddrError::BadPadding
  )]
  #[case::five_leftover_bits(
    {
      let mut groups = groups_of(&P2PKH_PAYLOAD);
      groups.push(0);
      bech32m_of_groups("dash", &groups)
    },
    PlatformAddrError::BadPadding
  )]
  #[case::short_hash(
    bech32::encode_lower::<Bech32m>(Hrp::parse("dash").unwrap(), &P2PKH_PAYLOAD[..20]).unwrap(),
    PlatformAddrError::BadLength { len: 20 }
  )]
  #[case::ninety_chars(
    bech32::encode_lower::<Bech32m>(Hrp::parse("dash").unwrap(), &[0xb0; 49]).unwrap(),
    PlatformAddrError::BadLength { len: 49 }
  )]
  #[case::ninety_one_chars(
    bech32::encode_lower::<Bech32m>(Hrp::parse("dash").unwrap(), &[0xb0; 50]).unwrap(),
    PlatformAddrError::InvalidEncoding
  )]
  #[case::unknown_type(
    bech32::encode_lower::<Bech32m>(Hrp::parse("dash").unwrap(), &hex!("00f7da0a2b5cbd4ff6bb2c4d89b67d2f3ffeec0525")).unwrap(),
    PlatformAddrError::UnknownType { type_byte: 0 }
  )]
  fn from_platform_rejects(#[case] addr: String, #[case] error: PlatformAddrError) {
    assert_eq!(Recipient::from_platform(&addr, &MAINNET), Err(error));
  }

  #[rstest]
  fn platform_lengths_bracket_the_bech32_limit() {
    let at_limit = bech32::encode_lower::<Bech32m>(Hrp::parse("dash").unwrap(), &[0xb0; 49]).unwrap();
    assert_eq!(at_limit.len(), BECH32_MAX_LEN);
  }
}
