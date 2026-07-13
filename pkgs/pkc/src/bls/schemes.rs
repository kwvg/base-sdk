//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! BLS scheme trait and marker types.

/// BLS scheme discriminator baked into the type system.
pub trait BlsSchemeId: 'static {
  /// `TypeId` constant for `BlsPkBytes<Self>`.
  const PK_TYPE_ID: u32;
  /// `TypeId` constant for `BlsSkBytes<Self>`.
  const SK_TYPE_ID: u32;
  /// `TypeId` constant for `BlsSigBytes<Self>`.
  const SIG_TYPE_ID: u32;
  /// Human-readable scheme label for `Debug`/`Display`.
  const LABEL: &'static str;
}

/// Legacy (Chia) BLS scheme marker.
#[derive(Debug)]
pub enum BlsScChia {}

impl BlsSchemeId for BlsScChia {
  // xxh32(b"BlsPkBytesChia", 0)
  const PK_TYPE_ID: u32 = 0xE377_6DA7;
  // xxh32(b"BlsSkBytesChia", 0)
  const SK_TYPE_ID: u32 = 0x3D50_6855;
  // xxh32(b"BlsSigBytesChia", 0)
  const SIG_TYPE_ID: u32 = 0xEF4A_E265;
  const LABEL: &'static str = "Chia";
}

/// IETF-standard BLS scheme marker.
#[derive(Debug)]
pub enum BlsScIetf {}

impl BlsSchemeId for BlsScIetf {
  // xxh32(b"BlsPkBytesIetf", 0)
  const PK_TYPE_ID: u32 = 0x6D54_3438;
  // xxh32(b"BlsSkBytesIetf", 0)
  const SK_TYPE_ID: u32 = 0xB5CE_BF45;
  // xxh32(b"BlsSigBytesIetf", 0)
  const SIG_TYPE_ID: u32 = 0xF57D_EF57;
  const LABEL: &'static str = "Ietf";
}
