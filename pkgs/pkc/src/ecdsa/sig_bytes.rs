//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! secp256k1 signature byte bag.

use dash_types::make_bytes;

make_bytes! {
  /// Raw compact ECDSA signature bytes.
  EcdsaSigBytes, 64
}
