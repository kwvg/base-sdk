//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Codec helpers for P2P message types.

/// Generates `Encodable` + `Decodable` with P2P payload size limit.
macro_rules! impl_p2p {
  ($ty:ty) => {
    dash_types::impl_type!($ty, crate::encode::MAX_P2P_PAYLOAD);
  };
}
pub(crate) use impl_p2p;
