/**
 * Copyright (c) 2026-present, The Dash Core developers
 * SPDX-License-Identifier: MIT
 * See the accompanying file LICENSE or https://opensource.org/license/MIT
 *
 * @id base-sdk/import-rules
 * @name Import rules
 * @description Prohibits direct alloc imports outside prelude.rs.
 * @kind problem
 * @precision high
 * @problem.severity warning
 * @tags style
 */

import lib.files
import rust

/** Holds if `u` imports directly from `alloc` outside `prelude.rs`. */
predicate directAllocImport(Use u) {
  usePrefix(u) = "alloc" and
  not fileOf(u).getBaseName() = "prelude.rs" and
  not fileOf(u).getAbsolutePath().matches("%/prelude/mod.rs")
}

from Use u, string message
where
  directAllocImport(u) and
  message = "use crate::prelude instead of direct alloc import"
select u, message
