//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Shared types and macros for the Dash SDK.

#![no_std]

extern crate alloc;
extern crate self as dash_types;
#[cfg(feature = "std")]
extern crate std;

mod entity;
mod hex;
mod macros;
#[allow(unused_imports, reason = "ergonomic shim, exports may be unused")]
mod prelude;
mod uint;

pub mod codec;
#[cfg(feature = "serde")]
pub mod serialize;

pub use dash_types_marker::{TypeId, Unencodable};
pub use entity::{BufferDecoder, VecEncoder, MAX_SER_SIZE};

#[doc(hidden)]
pub mod __private {
  pub use bitcoin_consensus_encoding;
  #[cfg(feature = "serde")]
  pub use hex_conservative;
}
