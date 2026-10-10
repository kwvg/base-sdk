//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Shared masternode collateral template script.

/// Shared masternode collateral script, `0x04 "DSHC" OP_DROP OP_TRUE`.
///
/// Anyone can spend it at the script layer. Consensus allows it only as the
/// collateral of a shared ProRegTx, and only a ProDisTx may spend it.
pub const SHARED_COLLATERAL_SCRIPT: [u8; 7] = [0x04, b'D', b'S', b'H', b'C', 0x75, 0x51];

/// Tells whether `script` is exactly [`SHARED_COLLATERAL_SCRIPT`].
pub fn is_shared_collateral_script(script: &[u8]) -> bool {
  script == SHARED_COLLATERAL_SCRIPT
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::opcode::Opcode;

  use dash_types::Numeric;
  use hex_conservative::hex;
  use rstest::rstest;

  #[rstest]
  fn template_pushes_dshc_then_drops_it() {
    assert_eq!(SHARED_COLLATERAL_SCRIPT, hex!("04445348437551"));
    assert_eq!(SHARED_COLLATERAL_SCRIPT[5], Opcode::Drop.to_base());
    assert_eq!(SHARED_COLLATERAL_SCRIPT[6], Opcode::Op1.to_base());
  }

  #[rstest]
  #[case::exact(&hex!("04445348437551"), true)]
  #[case::empty(&[], false)]
  #[case::truncated(&hex!("044453484375"), false)]
  #[case::extended(&hex!("0444534843755100"), false)]
  #[case::other_tag(&hex!("04445348447551"), false)]
  fn template_matches_exactly(#[case] script: &[u8], #[case] expected: bool) {
    assert_eq!(is_shared_collateral_script(script), expected);
  }
}
