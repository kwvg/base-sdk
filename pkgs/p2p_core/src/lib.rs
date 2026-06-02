//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Dash P2P message types for BIP324 encrypted transport.

#![no_std]

extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

#[allow(unused_imports, reason = "ergonomic shim, exports may be unused")]
mod prelude;

pub mod encode;
pub mod error;
pub mod msg;
pub mod primitives;
pub mod v2;

pub use error::P2pDecodeError;
pub use msg::DashNetworkMessage;
pub use primitives::{
  command::CommandString,
  compressed_header::CompressionState,
  filter_type::FilterType,
  governance::{GovernanceObject, GovernanceVote, VoteOutcome, VoteSignal},
  inventory::{InvType, Inventory},
  magic::Magic,
  mn_list::{MnListDiffPayload, SimplifiedMnListEntry},
  net_addr::{AddrV2, AddrV2Entry, NetAddr, TimestampedAddr},
  protocol_version::ProtocolVersion,
  service_flags::ServiceFlags,
  short_id::ShortId,
  user_agent::UserAgent,
};
