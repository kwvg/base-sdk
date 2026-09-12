//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! BLS public key byte bag.

use crate::bls::BlsSchemeId;

use bitcoin_hashes::sha256d::Hash as Sha256d;
use dash_num::Hash256;
use dash_types::make_bytes;
use dash_types::Hashable;

/// Raw BLS public key length (G1 compressed).
pub const BLS_PK_LEN: usize = 48;

make_bytes! {
  /// Scheme-tagged BLS public key bytes (48 bytes, unvalidated).
  for[S: BlsSchemeId] BlsPkBytes<S>, BLS_PK_LEN
}

impl<S: BlsSchemeId> Hashable for BlsPkBytes<S> {
  type Hash = Hash256;

  fn hash(&self) -> Self::Hash {
    Hash256::from_bytes(Sha256d::hash(self.as_bytes()).to_byte_array())
  }
}
