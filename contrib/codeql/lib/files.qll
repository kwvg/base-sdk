/**
 * Copyright (c) 2026-present, The Dash Core developers
 * SPDX-License-Identifier: MIT
 * See the accompanying file LICENSE or https://opensource.org/license/MIT
 *
 * @description Location, file, and path helpers.
 */

import rust

/** Gets the start line of `n`. */
int startLine(Locatable n) { result = n.getLocation().getStartLine() }

/** Gets the end line of `n`. */
int endLine(Locatable n) { result = n.getLocation().getEndLine() }

/** Gets the file containing `n`. */
File fileOf(Locatable n) { result = n.getLocation().getFile() }

/**
 * Gets the effective start line of `u`, accounting for leading
 * attributes (e.g. `#[cfg(...)]`).
 */
int effectiveStartUse(Use u) {
  if exists(u.getAnAttr())
  then result = min(Attr a | a = u.getAnAttr() | startLine(a))
  else result = startLine(u)
}

/**
 * Gets the effective start line of a module declaration `m`,
 * accounting for leading attributes.
 */
int effectiveStartMod(Module m) {
  if exists(m.getAnAttr())
  then result = min(Attr a | a = m.getAnAttr() | startLine(a))
  else result = startLine(m)
}

/**
 * Gets the effective start line of an extern crate declaration `e`,
 * accounting for leading attributes.
 */
int effectiveStartExternCrate(ExternCrate e) {
  if exists(e.getAnAttr())
  then result = min(Attr a | a = e.getAnAttr() | startLine(a))
  else result = startLine(e)
}

/** Gets the root (qualifier-less) segment of path `p`. */
Path rootPath(Path p) {
  not exists(p.getQualifier()) and result = p
  or
  result = rootPath(p.getQualifier())
}

/** Gets the first path segment of use declaration `u`. */
string usePrefix(Use u) {
  result = rootPath(u.getUseTree().getPath()).getSegment().getIdentifier().getText()
}
