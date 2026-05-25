//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Public-key cryptography for Dash.

#![no_std]

extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

pub use dash_num::Hash256;

mod prelude;

#[cfg(any(feature = "bls_ietf", feature = "bls_chia"))]
mod common;

#[cfg(feature = "bls_chia")]
pub mod bls_chia;

#[cfg(feature = "bls_ietf")]
pub mod bls_ietf;

#[cfg(feature = "k256")]
pub mod k256;

#[cfg(feature = "std")]
pub mod worker;
