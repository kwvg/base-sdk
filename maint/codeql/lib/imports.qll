/**
 * Copyright (c) 2026-present, The Dash Core developers
 * SPDX-License-Identifier: MIT
 * See the accompanying file LICENSE or https://opensource.org/license/MIT
 *
 * @description Preamble classification building blocks for import ordering.
 */

import lib.files
import rust

/** Gets the human-readable label for group `g`. */
bindingset[g]
pragma[inline]
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
 * Holds if `u` lives inside a crate-root `__private` module
 * (intentional crate-level re-exports for macro support).
 */
predicate isMacroReexport(Use u) {
  exists(Module priv |
    priv.getName().getText() = "__private" and
    u.getParentNode() = priv.getItemList() and
    isRootModule(priv)
  )
}

/** Holds if `u` is an allowlisted re-export from a foreign crate. */
private predicate isAllowlistedReexport(Use u) {
  usePrefix(u) = "dash_types_marker" and
  fileOf(u).getAbsolutePath().matches("%pkgs/types/%")
  or
  usePrefix(u) = "dash_pkc" and
  u.getUseTree().getPath().getSegment().getIdentifier().getText() = "__PubKeyHash" and
  fileOf(u).getAbsolutePath().matches("%pkgs/script/%")
  or
  usePrefix(u) = "dash_types" and
  u.getUseTree().getPath().getSegment().getIdentifier().getText() = "__ScriptHash" and
  fileOf(u).getAbsolutePath().matches("%pkgs/script/%")
}

/**
 * Holds if `u` is a `pub use` that re-exports from a foreign crate.
 * The first path segment is not `crate`/`self`/`super` and does not
 * match a sibling `mod` or a root-level `mod` in the same file.
 * The root-level fallback covers macro-wrapped declarations whose
 * AST parent differs from the use site.
 */
predicate isForeignReexport(Use u) {
  isPublicUse(u) and
  not isAllowlistedReexport(u) and
  exists(string prefix |
    prefix = usePrefix(u) and
    not prefix = "crate" and
    not prefix = "self" and
    not prefix = "super" and
    not exists(Module m |
      m.getName().getText() = prefix and
      (
        // Direct sibling in the same scope.
        m.getParentNode() = u.getParentNode()
        or
        // Root-level module in the same file (covers macro-wrapped decls).
        fileOf(m) = fileOf(u) and
        isRootModule(m)
      )
    )
  )
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
pragma[noinline]
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

/** Materialises candidate adjacent pairs for join efficiency. */
pragma[nomagic]
private predicate candidatePair(
  Locatable a, Locatable b, File f, int groupA, int groupB, int endA, int effStartB
) {
  preambleItem(a, f, groupA, _, endA) and
  preambleItem(b, f, groupB, effStartB, _) and
  endA < effStartB and
  a.(AstNode).getParentNode() = b.(AstNode).getParentNode()
}

/**
 * Holds if `a` and `b` are adjacent preamble items in the same
 * file and scope with no non-preamble items between them.
 */
predicate consecutivePreamble(
  Locatable a, Locatable b, File f, int groupA, int groupB, int endA, int effStartB
) {
  candidatePair(a, b, f, groupA, groupB, endA, effStartB) and
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
