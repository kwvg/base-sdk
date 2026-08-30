/**
 * Copyright (c) 2026-present, The Dash Core developers
 * SPDX-License-Identifier: MIT
 * See the accompanying file LICENSE or https://opensource.org/license/MIT
 *
 * @description Location, file, and path helpers.
 */

import rust

/** Gets the start line of `n`. */
pragma[inline]
int startLine(Locatable n) { result = n.getLocation().getStartLine() }

/** Gets the end line of `n`. */
pragma[inline]
int endLine(Locatable n) { result = n.getLocation().getEndLine() }

/** Gets the file containing `n`. */
pragma[inline]
File fileOf(Locatable n) { result = n.getLocation().getFile() }

/** Gets an attribute of a preamble item (Use, Module, or ExternCrate). */
private Attr itemAttr(Item item) {
  result = item.(Use).getAnAttr() or
  result = item.(Module).getAnAttr() or
  result = item.(ExternCrate).getAnAttr()
}

/**
 * Gets the effective start line of `item`, accounting for leading
 * attributes (e.g. `#[cfg(...)]`).
 */
int effectiveStart(Item item) {
  if exists(itemAttr(item))
  then result = min(Attr a | a = itemAttr(item) | startLine(a))
  else result = startLine(item)
}

/** Gets the root (qualifier-less) segment of path `p`. */
Path rootPath(Path p) {
  result = p.getQualifier*() and
  not exists(result.getQualifier())
}

/** Materialises the repo-root-relative path for source files. */
pragma[nomagic]
predicate fileRelPath(File f, string relPath) {
  relPath = f.getAbsolutePath().regexpCapture(".*/(pkgs/.*)", 1)
}

/** Holds if `f` belongs to a crate in this workspace. */
predicate isWorkspaceFile(File f) { fileRelPath(f, _) }

/** Holds if module `m` is not nested inside another module. */
predicate isRootModule(Module m) {
  not exists(Module enclosing | m.getParentNode() = enclosing.getItemList())
}

/** Gets the first path segment of use declaration `u`. */
string usePrefix(Use u) {
  result = rootPath(u.getUseTree().getPath()).getSegment().getIdentifier().getText()
}
