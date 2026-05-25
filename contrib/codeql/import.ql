/**
 * Copyright (c) 2026-present, The Dash Core developers
 * SPDX-License-Identifier: MIT
 * See the accompanying file LICENSE or https://opensource.org/license/MIT
 *
 * @id base-sdk/import-rules
 * @name Import and definition rules
 * @description Rules surrounding usage of `mod`, `use` and shim enforcement.
 * @kind problem
 * @precision high
 * @problem.severity warning
 * @tags style
 */

import lib.paths
import rust

/** Holds if `u` imports directly from `alloc` outside `prelude.rs`. */
predicate directAllocImport(Use u) {
  usePrefix(u) = "alloc" and
  not u.getLocation().getFile().getBaseName() = "prelude.rs"
}

from Use u, string message
where
  (
    directAllocImport(u) and
    message = "use crate::prelude instead of direct alloc import"
  )
select u, message
