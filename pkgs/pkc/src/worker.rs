//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Generic parallel work distribution.
//!
//! Thin layer over rayon that parallelizes cryptographic operations without
//! coupling to any specific scheme. The caller provides the operation; the
//! worker handles thread pooling and work stealing.

use crate::prelude::*;

use rayon::prelude::*;

/// Verify N items in parallel. Returns per-item pass/fail.
pub fn par_verify<T, F>(items: &[T], verify: F) -> Vec<bool>
where
  T: Sync,
  F: Fn(&T) -> bool + Sync,
{
  items.par_iter().map(&verify).collect()
}

/// Map N items in parallel.
pub fn par_map<T, U, F>(items: &[T], f: F) -> Vec<U>
where
  T: Sync,
  U: Send,
  F: Fn(&T) -> U + Sync,
{
  items.par_iter().map(&f).collect()
}

/// Tree-reduce N items in parallel.
pub fn par_reduce<T, F>(items: Vec<T>, combine: F) -> Option<T>
where
  T: Send,
  F: Fn(T, T) -> T + Sync + Send,
{
  items.into_par_iter().reduce_with(combine)
}

/// Set the global thread pool size. Call once at startup.
/// Subsequent calls are silently ignored.
pub fn init(num_threads: usize) {
  let _ = rayon::ThreadPoolBuilder::new().num_threads(num_threads).build_global();
}
