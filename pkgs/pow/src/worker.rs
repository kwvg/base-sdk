//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Parallel proof-of-work hashing.

use crate::prelude::*;

use dash_num::Hash256;
use rayon::prelude::*;

/// Hash N inputs in parallel, returning one digest per input.
pub fn par_hash(inputs: &[&[u8]]) -> Vec<Hash256> {
  inputs.par_iter().map(|data| crate::hash(data)).collect()
}

/// Set the global thread pool size. Call once at startup.
/// Subsequent calls are silently ignored.
pub fn init(num_threads: usize) {
  let _ = rayon::ThreadPoolBuilder::new().num_threads(num_threads).build_global();
}
