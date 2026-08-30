/**
 * Copyright (c) 2026-present, The Dash Core developers
 * SPDX-License-Identifier: MIT
 * See the accompanying file LICENSE or https://opensource.org/license/MIT
 *
 * @id base-sdk/import-rules
 * @name Import grouping and ordering rules
 * @description Enforces import ordering with blank-line constraints.
 * @kind problem
 * @precision high
 * @problem.severity warning
 * @tags style
 */

import lib.files
import lib.fmt
import lib.imports
import lib.policy
import lib.source_lines
import rust

/** Materialises the file-to-cfg-line mapping. */
pragma[nomagic]
private predicate fileCfgLines(File f, int cfgLine) {
  exists(string relPath, string content |
    fileRelPath(f, relPath) and
    sourceLineContent(relPath, cfgLine, content) and
    content.matches("#[cfg%")
  )
}

/**
 * Holds if a `#[cfg]` attribute exists between lines `startAfter` and
 * `endBefore` in `f`. Cfg-gated items compiled out by the extractor
 * leave gaps that should not trigger the "unexpected blank line" rule.
 */
bindingset[f, startAfter, endBefore]
predicate hasCfgGatedGap(File f, int startAfter, int endBefore) {
  exists(int cfgLine |
    fileCfgLines(f, cfgLine) and
    cfgLine > startAfter and
    cfgLine < endBefore
  )
}

from Locatable item, string message
where
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
      not hasCfgGatedGap(f, endA, effStartB) and
      message = fmt("unexpected blank line within {0} group", groupLabel(groupA))
    )
  )
  or
  // Foreign module re-export from {lib,mod}.rs.
  exists(Use u |
    item = u and
    fileRelPath(fileOf(u), _) and
    isForeignReexport(u) and
    not isMacroReexport(u) and
    message = "pub use " + usePrefix(u) + ":: re-exports from a foreign crate"
  )
select item, message
