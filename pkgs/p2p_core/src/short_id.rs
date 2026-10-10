//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! V2 short ID mapping for BIP324 message framing.

use crate::command::CommandString;
use crate::ProtocolVersion;

use dash_types::type_id::Unencodable;

/// A resolved V2 short ID.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Unencodable)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct ShortId(pub u8);

impl ShortId {
  /// Long-format sentinel (a 12-byte command follows).
  pub const LONG_FORMAT: Self = Self(0);

  /// Returns `true` if this ID maps to a known command.
  pub const fn is_valid(self) -> bool {
    self.to_command_str().is_some()
  }

  /// Lowest peer version the short ID is sent to. Peers below it receive the
  /// long format.
  pub fn min_version(self) -> ProtocolVersion {
    match self.to_command() {
      Some(CommandString::PLATFORMBAN) => ProtocolVersion::PLATFORMBAN_V2_SHORT_ID,
      _ => ProtocolVersion::BIP324_BASELINE,
    }
  }

  /// Resolves the short ID to a `CommandString`, if known.
  pub fn to_command(self) -> Option<CommandString> {
    self.to_command_str().map(CommandString::from_static)
  }
}
