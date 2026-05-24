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

import lib.fmt
import lib.paths
import rust

/** Gets the effective start line of `u`, accounting for leading attributes. */
int effectiveStart(Use u) {
  if exists(u.getAnAttr())
  then result = min(Attr a | a = u.getAnAttr() | a.getLocation().getStartLine())
  else result = u.getLocation().getStartLine()
}

/**
 * Gets the ordering group of `u`.
 * 0 = crate/super, 1 = external, 2 = alloc/core/std.
 */
int importGroup(Use u) {
  exists(string prefix | prefix = usePrefix(u) |
    (prefix = "crate" or prefix = "super") and
    result = 0
    or
    (prefix = "alloc" or prefix = "core" or prefix = "std") and
    result = 2
    or
    not (
      prefix = "crate" or
      prefix = "super" or
      prefix = "alloc" or
      prefix = "core" or
      prefix = "std"
    ) and
    result = 1
  )
}

/** Gets the human-readable name for import group `g`. */
string groupName(int g) {
  g = 0 and result = "crate/super"
  or
  g = 1 and result = "external"
  or
  g = 2 and result = "alloc/core/std"
}

/** Holds if `a` and `b` are adjacent use declarations in the same scope. */
predicate consecutiveUses(Use a, Use b) {
  a.getLocation().getFile() = b.getLocation().getFile() and
  a.getLocation().getStartLine() < b.getLocation().getStartLine() and
  a.getParentNode() = b.getParentNode() and
  not exists(Use mid |
    mid.getLocation().getFile() = a.getLocation().getFile() and
    effectiveStart(mid) > a.getLocation().getStartLine() and
    effectiveStart(mid) < effectiveStart(b)
  ) and
  not exists(Item other |
    not other instanceof Use and
    other.getLocation().getFile() = a.getLocation().getFile() and
    other.getLocation().getStartLine() > a.getLocation().getEndLine() and
    other.getLocation().getStartLine() < effectiveStart(b)
  )
}

/** Holds if `u` imports directly from `alloc` outside `prelude.rs`. */
predicate directAllocImport(Use u) {
  usePrefix(u) = "alloc" and
  not u.getLocation().getFile().getBaseName() = "prelude.rs"
}

from Use u, string message
where
  (
    exists(Use prev |
      consecutiveUses(prev, u) and
      (
        importGroup(prev) > importGroup(u) and
        message =
          fmt("{0} import must appear before {1} imports", groupName(importGroup(u)),
            groupName(importGroup(prev)))
        or
        importGroup(prev) < importGroup(u) and
        effectiveStart(u) - prev.getLocation().getEndLine() < 2 and
        message =
          fmt("missing blank line between {0} and {1} import groups", groupName(importGroup(prev)),
            groupName(importGroup(u)))
        or
        importGroup(prev) = importGroup(u) and
        effectiveStart(u) - prev.getLocation().getEndLine() > 1 and
        message = fmt("unexpected blank line within {0} import group", groupName(importGroup(u)))
      )
    )
    or
    directAllocImport(u) and
    message = "use crate::prelude instead of direct alloc import"
  )
select u, message
