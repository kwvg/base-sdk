//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Codec helpers for primitives payload types.

/// Generates `Encodable` + `Decodable` with payload size limit.
macro_rules! impl_payload {
  ($ty:ty) => {
    dash_types::impl_type!($ty, crate::MAX_EXTRA_PAYLOAD_SIZE);
  };
}
pub(crate) use impl_payload;
