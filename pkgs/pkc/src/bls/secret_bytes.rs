//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! BLS secret key byte bag.

use crate::bls::BlsSchemeId;

use bitcoin_hashes::sha256d::Hash as Sha256d;
use dash_num::Hash256;
use dash_types::make_sbytes;
use dash_types::Hashable;

/// Raw BLS secret key length (scalar).
pub const BLS_SK_LEN: usize = 32;

make_sbytes! {
  /// Scheme-tagged BLS secret key bytes (32 bytes, zeroized on drop).
  for[S: BlsSchemeId] BlsSkBytes<S>, BLS_SK_LEN
}

impl<S: BlsSchemeId> Hashable for BlsSkBytes<S> {
  type Hash = Hash256;

  fn hash(&self) -> Self::Hash {
    Hash256::from_bytes(Sha256d::hash(self.as_bytes()).to_byte_array())
  }
}
