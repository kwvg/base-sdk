//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Consensus-compatible numeric types.
//!
//! Provides hash blob types ([`Hash512`], [`Hash256`], [`Hash160`])
//! and the [`Arith256`] arithmetic integer type.

#![no_std]

extern crate alloc;
#[cfg(feature = "std")]
extern crate std;

mod arith;
mod arith256;
mod compact;
mod error;
mod hash;
mod hash_encoding;
#[allow(unused_imports, reason = "ergonomic shim, exports may be unused")]
mod prelude;
#[cfg(feature = "serde")]
#[doc(hidden)]
pub mod serialize;
#[doc(hidden)]
pub mod util;

#[doc(hidden)]
pub mod __private {
  pub use bitcoin_consensus_encoding;
}

pub use arith::ArithInt;
pub use arith256::Arith256;
pub use compact::{CompactTarget, DecodedTarget};
pub use error::ParseHexError;
pub use hash::{Hash160, Hash256, Hash512, HashBlob};
pub use hash_encoding::{HashDecoder, HashDecoderError, HashTypeDecoder};
