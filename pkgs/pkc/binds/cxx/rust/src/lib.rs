//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Diplomat FFI bridge exposing dash-pkc BLS to C++.

#![no_std]
// The diplomat bridge macro emits `#[no_mangle]` extern functions,
// which the `unsafe_code` lint reports.
#![allow(unsafe_code)]
// The FFI surface intentionally exposes C++-shaped inherent
// methods (`eq`, `len` builders without `is_empty`).
#![allow(clippy::should_implement_trait, clippy::len_without_is_empty)]

extern crate alloc;

mod bridge;

pub use bridge::ffi;
