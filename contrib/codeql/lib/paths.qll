/**
 * Copyright (c) 2026-present, The Dash Core developers
 * SPDX-License-Identifier: MIT
 * See the accompanying file LICENSE or https://opensource.org/license/MIT
 *
 * Path manipulation helpers for Rust.
 */

import rust

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
