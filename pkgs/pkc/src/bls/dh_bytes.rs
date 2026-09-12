//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! BLS Diffie-Hellman shared key byte bag.

use crate::bls::BlsSchemeId;

use dash_types::make_sbytes;

/// Raw shared secret length (G1 compressed).
pub const BLS_DH_LEN: usize = 48;

make_sbytes! {
  /// A scheme-tagged Diffie-Hellman shared key, `sk * peer_pk`.
  for[S: BlsSchemeId] BlsDhBytes<S>, BLS_DH_LEN, nocodec
}
