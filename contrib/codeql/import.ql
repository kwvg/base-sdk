/**
 * Copyright (c) 2026-present, The Dash Core developers
 * SPDX-License-Identifier: MIT
 * See the accompanying file LICENSE or https://opensource.org/license/MIT
 *
 * @id base-sdk/import-rules
 * @name Import grouping and ordering rules
 * @description Enforces import ordering with blank-line constraints, prohibits non-prelude alloc imports.
 * @kind problem
 * @precision high
 * @problem.severity warning
 * @tags style
 */

import lib.files
import lib.fmt
import rust

/** Gets the human-readable label for group `g`. */
string groupLabel(int g) {
  g = 0 and result = "extern crate"
  or
  g = 1 and result = "mod"
  or
  g = 2 and result = "use crate/super"
  or
  g = 3 and result = "use external"
  or
  g = 4 and result = "use alloc/core/std"
  or
  g = 5 and result = "pub mod"
  or
  g = 6 and result = "pub use crate/super"
  or
  g = 7 and result = "pub use external"
  or
  g = 8 and result = "pub use alloc/core/std"
}

/**
 * Holds if use declaration `u` has `pub` visibility.
 *
 * Bare `pub` has a Visibility node with no path; `pub(crate)` and
 * `pub(super)` carry a path whose segment is "crate" or "super".
 */
predicate isPublicUse(Use u) {
  exists(u.getVisibility()) and
  not exists(u.getVisibility().getPath())
}

/**
 * Holds if module declaration `m` has `pub` visibility.
 *
 * See `isPublicUse` for the visibility encoding rationale.
 */
predicate isPublicMod(Module m) {
  exists(m.getVisibility()) and
  not exists(m.getVisibility().getPath())
}

/**
 * Gets the use-declaration base group (ignoring pub/priv).
 * 2 = crate/super, 3 = external, 4 = alloc/core/std.
 */
int useBaseGroup(Use u) {
  exists(string prefix | prefix = usePrefix(u) |
    (prefix = "crate" or prefix = "super" or prefix = "self") and
    result = 2
    or
    (prefix = "alloc" or prefix = "core" or prefix = "std") and
    result = 4
    or
    not prefix = "crate" and
    not prefix = "super" and
    not prefix = "self" and
    not prefix = "alloc" and
    not prefix = "core" and
    not prefix = "std" and
    result = 3
  )
}

/** Gets the preamble group of use declaration `u`. */
int useGroup(Use u) {
  isPublicUse(u) and result = useBaseGroup(u) + 4
  or
  not isPublicUse(u) and result = useBaseGroup(u)
}

/** Gets the preamble group of a file-level module declaration `m`. */
int modGroup(Module m) {
  not exists(m.getItemList()) and
  (
    isPublicMod(m) and result = 5
    or
    not isPublicMod(m) and result = 1
  )
}

/**
 * Unifies preamble items into (file, group, effectiveStart, endLine)
 * tuples for ordering analysis.
 */
predicate preambleItem(Locatable item, File f, int group, int effStart, int end) {
  exists(Use u |
    item = u and
    f = fileOf(u) and
    group = useGroup(u) and
    effStart = effectiveStart(u) and
    end = endLine(u)
  )
  or
  exists(Module m |
    item = m and
    f = fileOf(m) and
    group = modGroup(m) and
    effStart = effectiveStart(m) and
    end = endLine(m)
  )
  or
  exists(ExternCrate e |
    item = e and
    f = fileOf(e) and
    group = 0 and
    effStart = effectiveStart(e) and
    end = endLine(e)
  )
}

/**
 * Holds if `a` and `b` are adjacent preamble items in the same
 * file and scope with no non-preamble items between them.
 */
predicate consecutivePreamble(
  Locatable a, Locatable b, File f, int groupA, int groupB, int endA, int effStartB
) {
  preambleItem(a, f, groupA, _, endA) and
  preambleItem(b, f, groupB, effStartB, _) and
  endA < effStartB and
  a.(AstNode).getParentNode() = b.(AstNode).getParentNode() and
  // No other preamble item between them.
  not exists(Locatable mid, int midStart |
    preambleItem(mid, f, _, midStart, _) and
    midStart > endA and
    midStart < effStartB
  ) and
  // No non-preamble item between them.
  not exists(Item other |
    not preambleItem(other, f, _, _, _) and
    fileOf(other) = f and
    startLine(other) > endA and
    startLine(other) < effStartB
  )
}

/** Holds if `u` imports directly from `alloc` outside `prelude.rs`. */
predicate directAllocImport(Use u) {
  usePrefix(u) = "alloc" and
  not fileOf(u).getBaseName() = "prelude.rs" and
  not fileOf(u).getAbsolutePath().matches("%/prelude/mod.rs")
}

from Locatable item, string message
where
  (
    exists(Locatable prev, File f, int groupA, int groupB, int endA, int effStartB |
      consecutivePreamble(prev, item, f, groupA, groupB, endA, effStartB) and
      (
        // Group decreased: wrong order.
        groupA > groupB and
        message = fmt("{0} must appear before {1}", groupLabel(groupB), groupLabel(groupA))
        or
        // Group increased but no blank line between them.
        groupA < groupB and
        effStartB - endA < 2 and
        message =
          fmt("missing blank line between {0} and {1}", groupLabel(groupA), groupLabel(groupB))
        or
        // Same group but spurious blank line within it.
        groupA = groupB and
        effStartB - endA > 1 and
        message = fmt("unexpected blank line within {0} group", groupLabel(groupA))
      )
    )
    or
    exists(Use u |
      item = u and
      directAllocImport(u) and
      message = "use crate::prelude instead of direct alloc import"
    )
  )
select item, message
