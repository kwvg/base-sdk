//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Script opcodes as defined by the consensus rules.

use core::fmt;

/// Generates the [`Opcode`] enum, `from_u8`, `to_u8`, and `Display` from a
/// single table.
macro_rules! define_opcodes {
  (
    $(
      $(#[$attr:meta])*
      $variant:ident = $byte:literal => $display:literal
    ),*
    $(,)?
  ) => {
    /// Script opcode.
    ///
    /// Every variant corresponds to exactly one byte value on the wire. Bytes `0x01..=0x4b` are
    /// direct data pushes (the byte *is* the push length); use [`Opcode::is_direct_push`] to
    /// test for them.
    #[derive(Clone, Copy, PartialEq, Eq, Hash)]
    #[repr(u8)]
    pub enum Opcode {
      $(
        $(#[$attr])*
        $variant = $byte,
      )*
    }

    impl Opcode {
      /// Converts a raw byte to the corresponding opcode.
      ///
      /// Bytes in the direct-push range `0x01..=0x4b` and any unmapped gaps map to
      /// [`InvalidOpcode`](Opcode::InvalidOpcode). Use [`is_direct_push`](Opcode::is_direct_push)
      /// to test for the push range before calling this.
      pub const fn from_u8(byte: u8) -> Self {
        match byte {
          $( $byte => Self::$variant, )*
          _ => Self::InvalidOpcode,
        }
      }

      /// Converts to the raw byte value.
      pub const fn to_u8(self) -> u8 {
        self as u8
      }
    }

    impl fmt::Display for Opcode {
      fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
          $( Self::$variant => f.write_str($display), )*
        }
      }
    }
  };
}

define_opcodes! {
  /// Push empty byte array onto the stack.
  Op0 = 0x00 => "OP_0",
  /// Next byte is the number of bytes to push.
  PushData1 = 0x4c => "OP_PUSHDATA1",
  /// Next two bytes (LE) are the number of bytes to push.
  PushData2 = 0x4d => "OP_PUSHDATA2",
  /// Next four bytes (LE) are the number of bytes to push.
  PushData4 = 0x4e => "OP_PUSHDATA4",
  /// Push the value -1 onto the stack.
  Op1Negate = 0x4f => "OP_1NEGATE",
  /// Reserved (causes script failure if executed).
  Reserved = 0x50 => "OP_RESERVED",
  /// Push the value 1 onto the stack.
  Op1 = 0x51 => "OP_1",
  /// Push the value 2.
  Op2 = 0x52 => "OP_2",
  /// Push the value 3.
  Op3 = 0x53 => "OP_3",
  /// Push the value 4.
  Op4 = 0x54 => "OP_4",
  /// Push the value 5.
  Op5 = 0x55 => "OP_5",
  /// Push the value 6.
  Op6 = 0x56 => "OP_6",
  /// Push the value 7.
  Op7 = 0x57 => "OP_7",
  /// Push the value 8.
  Op8 = 0x58 => "OP_8",
  /// Push the value 9.
  Op9 = 0x59 => "OP_9",
  /// Push the value 10.
  Op10 = 0x5a => "OP_10",
  /// Push the value 11.
  Op11 = 0x5b => "OP_11",
  /// Push the value 12.
  Op12 = 0x5c => "OP_12",
  /// Push the value 13.
  Op13 = 0x5d => "OP_13",
  /// Push the value 14.
  Op14 = 0x5e => "OP_14",
  /// Push the value 15.
  Op15 = 0x5f => "OP_15",
  /// Push the value 16.
  Op16 = 0x60 => "OP_16",

  /// Do nothing.
  Nop = 0x61 => "OP_NOP",
  /// Reserved (causes script failure if executed).
  Ver = 0x62 => "OP_VER",
  /// Execute following opcodes if top of stack is true.
  If = 0x63 => "OP_IF",
  /// Execute following opcodes if top of stack is false.
  NotIf = 0x64 => "OP_NOTIF",
  /// Reserved (causes script failure if executed).
  VerIf = 0x65 => "OP_VERIF",
  /// Reserved (causes script failure if executed).
  VerNotIf = 0x66 => "OP_VERNOTIF",
  /// Execute following opcodes if preceding OP_IF was not taken.
  Else = 0x67 => "OP_ELSE",
  /// End an OP_IF/OP_ELSE block.
  EndIf = 0x68 => "OP_ENDIF",
  /// Remove top stack item; fail if it is false.
  Verify = 0x69 => "OP_VERIFY",
  /// Mark transaction output as unspendable.
  Return = 0x6a => "OP_RETURN",

  /// Move top item to the alt stack.
  ToAltStack = 0x6b => "OP_TOALTSTACK",
  /// Move top item from the alt stack to the main stack.
  FromAltStack = 0x6c => "OP_FROMALTSTACK",
  /// Remove the top two items.
  Drop2 = 0x6d => "OP_2DROP",
  /// Duplicate the top two items.
  Dup2 = 0x6e => "OP_2DUP",
  /// Duplicate the top three items.
  Dup3 = 0x6f => "OP_3DUP",
  /// Copy items 3 and 4 to the top.
  Over2 = 0x70 => "OP_2OVER",
  /// Move items 5 and 6 to the top.
  Rot2 = 0x71 => "OP_2ROT",
  /// Swap the top two pairs.
  Swap2 = 0x72 => "OP_2SWAP",
  /// Duplicate the top item if it is non-zero.
  IfDup = 0x73 => "OP_IFDUP",
  /// Push the stack size.
  Depth = 0x74 => "OP_DEPTH",
  /// Remove the top item.
  Drop = 0x75 => "OP_DROP",
  /// Duplicate the top item.
  Dup = 0x76 => "OP_DUP",
  /// Remove the second-to-top item.
  Nip = 0x77 => "OP_NIP",
  /// Copy the second-to-top item to the top.
  Over = 0x78 => "OP_OVER",
  /// Copy the n-th item to the top.
  Pick = 0x79 => "OP_PICK",
  /// Move the n-th item to the top.
  Roll = 0x7a => "OP_ROLL",
  /// Rotate the top three items.
  Rot = 0x7b => "OP_ROT",
  /// Swap the top two items.
  Swap = 0x7c => "OP_SWAP",
  /// Copy the top item below the second item.
  Tuck = 0x7d => "OP_TUCK",

  /// Concatenate two byte strings (disabled).
  Cat = 0x7e => "OP_CAT",
  /// Split a byte string (disabled).
  Split = 0x7f => "OP_SPLIT",

  /// Convert a number to a byte string of given length (disabled).
  Num2Bin = 0x80 => "OP_NUM2BIN",
  /// Convert a byte string to a number (disabled).
  Bin2Num = 0x81 => "OP_BIN2NUM",
  /// Push the byte length of the top item.
  Size = 0x82 => "OP_SIZE",

  /// Bitwise NOT (disabled).
  Invert = 0x83 => "OP_INVERT",
  /// Bitwise AND (disabled).
  And = 0x84 => "OP_AND",
  /// Bitwise OR (disabled).
  Or = 0x85 => "OP_OR",
  /// Bitwise XOR (disabled).
  Xor = 0x86 => "OP_XOR",
  /// Push true if the top two items are byte-for-byte equal.
  Equal = 0x87 => "OP_EQUAL",
  /// Same as OP_EQUAL followed by OP_VERIFY.
  EqualVerify = 0x88 => "OP_EQUALVERIFY",
  /// Reserved (causes script failure if executed).
  Reserved1 = 0x89 => "OP_RESERVED1",
  /// Reserved (causes script failure if executed).
  Reserved2 = 0x8a => "OP_RESERVED2",

  /// Add 1 to the top item.
  Add1 = 0x8b => "OP_1ADD",
  /// Subtract 1 from the top item.
  Sub1 = 0x8c => "OP_1SUB",
  /// Multiply by 2 (disabled).
  Mul2 = 0x8d => "OP_2MUL",
  /// Divide by 2 (disabled).
  Div2 = 0x8e => "OP_2DIV",
  /// Negate the top item.
  Negate = 0x8f => "OP_NEGATE",
  /// Absolute value of the top item.
  Abs = 0x90 => "OP_ABS",
  /// Boolean NOT.
  Not = 0x91 => "OP_NOT",
  /// Push true if the top item is not zero.
  NotEqual0 = 0x92 => "OP_0NOTEQUAL",
  /// Add the top two items.
  Add = 0x93 => "OP_ADD",
  /// Subtract the top item from the second.
  Sub = 0x94 => "OP_SUB",
  /// Multiply (disabled).
  Mul = 0x95 => "OP_MUL",
  /// Integer divide (disabled).
  Div = 0x96 => "OP_DIV",
  /// Modulo (disabled).
  Mod = 0x97 => "OP_MOD",
  /// Left shift (disabled).
  LShift = 0x98 => "OP_LSHIFT",
  /// Right shift (disabled).
  RShift = 0x99 => "OP_RSHIFT",
  /// Boolean AND of the top two items.
  BoolAnd = 0x9a => "OP_BOOLAND",
  /// Boolean OR of the top two items.
  BoolOr = 0x9b => "OP_BOOLOR",
  /// Push true if the top two items are numerically equal.
  NumEqual = 0x9c => "OP_NUMEQUAL",
  /// Same as OP_NUMEQUAL followed by OP_VERIFY.
  NumEqualVerify = 0x9d => "OP_NUMEQUALVERIFY",
  /// Push true if the top two items are not equal.
  NumNotEqual = 0x9e => "OP_NUMNOTEQUAL",
  /// Push true if the second item is less than the top.
  LessThan = 0x9f => "OP_LESSTHAN",
  /// Push true if the second item is greater than the top.
  GreaterThan = 0xa0 => "OP_GREATERTHAN",
  /// Push true if the second item is <= the top.
  LessThanOrEqual = 0xa1 => "OP_LESSTHANOREQUAL",
  /// Push true if the second item is >= the top.
  GreaterThanOrEqual = 0xa2 => "OP_GREATERTHANOREQUAL",
  /// Push the smaller of the top two items.
  Min = 0xa3 => "OP_MIN",
  /// Push the larger of the top two items.
  Max = 0xa4 => "OP_MAX",
  /// Push true if x is within the range [min, max).
  Within = 0xa5 => "OP_WITHIN",

  /// RIPEMD-160 hash of the top item.
  Ripemd160 = 0xa6 => "OP_RIPEMD160",
  /// SHA-1 hash of the top item.
  Sha1 = 0xa7 => "OP_SHA1",
  /// SHA-256 hash of the top item.
  Sha256 = 0xa8 => "OP_SHA256",
  /// RIPEMD-160(SHA-256(x)) of the top item.
  Hash160 = 0xa9 => "OP_HASH160",
  /// SHA-256(SHA-256(x)) of the top item.
  Hash256 = 0xaa => "OP_HASH256",
  /// Mark the start of signature-checked data.
  CodeSeparator = 0xab => "OP_CODESEPARATOR",
  /// Verify a signature against a public key.
  CheckSig = 0xac => "OP_CHECKSIG",
  /// Same as OP_CHECKSIG followed by OP_VERIFY.
  CheckSigVerify = 0xad => "OP_CHECKSIGVERIFY",
  /// Verify an m-of-n multisig.
  CheckMultiSig = 0xae => "OP_CHECKMULTISIG",
  /// Same as OP_CHECKMULTISIG followed by OP_VERIFY.
  CheckMultiSigVerify = 0xaf => "OP_CHECKMULTISIGVERIFY",

  /// Do nothing (reserved for future soft-fork).
  Nop1 = 0xb0 => "OP_NOP1",
  /// Fail unless the lock-time condition is met (BIP65).
  CheckLockTimeVerify = 0xb1 => "OP_CHECKLOCKTIMEVERIFY",
  /// Fail unless the sequence condition is met (BIP112).
  CheckSequenceVerify = 0xb2 => "OP_CHECKSEQUENCEVERIFY",
  /// Do nothing (reserved for future soft-fork).
  Nop4 = 0xb3 => "OP_NOP4",
  /// Do nothing (reserved for future soft-fork).
  Nop5 = 0xb4 => "OP_NOP5",
  /// Do nothing (reserved for future soft-fork).
  Nop6 = 0xb5 => "OP_NOP6",
  /// Do nothing (reserved for future soft-fork).
  Nop7 = 0xb6 => "OP_NOP7",
  /// Do nothing (reserved for future soft-fork).
  Nop8 = 0xb7 => "OP_NOP8",
  /// Do nothing (reserved for future soft-fork).
  Nop9 = 0xb8 => "OP_NOP9",
  /// Do nothing (reserved for future soft-fork).
  Nop10 = 0xb9 => "OP_NOP10",

  /// Verify a data signature (not part of transaction digest).
  CheckDataSig = 0xba => "OP_CHECKDATASIG",
  /// Same as OP_CHECKDATASIG followed by OP_VERIFY.
  CheckDataSigVerify = 0xbb => "OP_CHECKDATASIGVERIFY",
  /// Invalid opcode (causes immediate script failure).
  InvalidOpcode = 0xff => "OP_INVALIDOPCODE",
}

// Aliases matching the canonical naming

impl Opcode {
  /// Alias: `OP_FALSE` = [`Op0`](Opcode::Op0).
  pub const FALSE: Self = Self::Op0;
  /// Alias: `OP_TRUE` = [`Op1`](Opcode::Op1).
  pub const TRUE: Self = Self::Op1;
  /// Alias: `OP_NOP2` = [`CheckLockTimeVerify`](Opcode::CheckLockTimeVerify).
  pub const NOP2: Self = Self::CheckLockTimeVerify;
  /// Alias: `OP_NOP3` = [`CheckSequenceVerify`](Opcode::CheckSequenceVerify).
  pub const NOP3: Self = Self::CheckSequenceVerify;
}

impl Opcode {
  /// Returns `true` when the byte is a direct data push (`0x01..=0x4b`),
  /// meaning the byte itself is the push length.
  pub const fn is_direct_push(byte: u8) -> bool {
    byte >= 0x01 && byte <= 0x4b
  }

  /// Returns `true` for opcodes counted toward the legacy sigop limit.
  pub const fn is_count_sigop(self) -> bool {
    matches!(
      self,
      Self::CheckSig | Self::CheckSigVerify | Self::CheckMultiSig | Self::CheckMultiSigVerify
    )
  }
}

impl fmt::Debug for Opcode {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "Opcode({:#04x})", self.to_u8())
  }
}

#[cfg(test)]
mod tests {
  use super::Opcode;

  #[test]
  fn round_trip_named_opcodes() {
    let cases: &[(u8, Opcode)] = &[
      (0x00, Opcode::Op0),
      (0x6a, Opcode::Return),
      (0x76, Opcode::Dup),
      (0xa9, Opcode::Hash160),
      (0xac, Opcode::CheckSig),
      (0x88, Opcode::EqualVerify),
      (0x87, Opcode::Equal),
      (0xb1, Opcode::CheckLockTimeVerify),
      (0xff, Opcode::InvalidOpcode),
    ];
    for &(byte, expected) in cases {
      assert_eq!(Opcode::from_u8(byte), expected);
      assert_eq!(expected.to_u8(), byte);
    }
  }

  #[test]
  fn direct_push_range() {
    assert!(!Opcode::is_direct_push(0x00));
    assert!(Opcode::is_direct_push(0x01));
    assert!(Opcode::is_direct_push(0x4b));
    assert!(!Opcode::is_direct_push(0x4c));
  }

  #[test]
  fn aliases() {
    assert_eq!(Opcode::FALSE, Opcode::Op0);
    assert_eq!(Opcode::TRUE, Opcode::Op1);
    assert_eq!(Opcode::NOP2, Opcode::CheckLockTimeVerify);
    assert_eq!(Opcode::NOP3, Opcode::CheckSequenceVerify);
  }

  #[test]
  fn unmapped_bytes_return_invalid() {
    // 0x01..=0x4b are direct pushes, not named opcodes
    assert_eq!(Opcode::from_u8(0x01), Opcode::InvalidOpcode);
    assert_eq!(Opcode::from_u8(0x4b), Opcode::InvalidOpcode);
    assert_eq!(Opcode::from_u8(0xcc), Opcode::InvalidOpcode);
  }

  #[test]
  fn display_formatting() {
    use crate::prelude::*;

    assert_eq!(Opcode::Dup.to_string(), "OP_DUP");
    assert_eq!(Opcode::Return.to_string(), "OP_RETURN");
    assert_eq!(Opcode::CheckLockTimeVerify.to_string(), "OP_CHECKLOCKTIMEVERIFY");
  }
}
