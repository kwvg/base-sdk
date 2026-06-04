//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Network parameters for Dash (mainnet, testnet3, regtest).

#![no_std]

extern crate alloc;
#[cfg(feature = "std")]
extern crate std;

#[allow(unused_imports, reason = "ergonomic shim, exports may be unused")]
mod prelude;

#[path = "mainnet.rs"]
pub mod main;
pub mod regtest;
pub mod test3;
pub mod types;
