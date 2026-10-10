//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Scripting and addressing.

#![no_std]

extern crate alloc;
#[cfg(feature = "std")]
extern crate std;

mod addrs;
mod collateral;
mod opcode;
#[allow(unused_imports, reason = "ergonomic shim, exports may be unused")]
mod prelude;
mod sigops;

pub use addrs::{AddrParams, Recipient};
pub use collateral::{is_shared_collateral_script, SHARED_COLLATERAL_SCRIPT};
pub use dash_pkc::__private::__EcdsaPkHash as PubKeyHash;
pub use dash_types::__private::__ScriptHash as ScriptHash;
pub use opcode::Opcode;
pub use sigops::legacy_sigop_count;
