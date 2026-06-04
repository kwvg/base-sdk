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
