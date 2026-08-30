/**
 * Copyright (c) 2026-present, The Dash Core developers
 * SPDX-License-Identifier: MIT
 * See the accompanying file LICENSE or https://opensource.org/license/MIT
 *
 * @description Provides string formatting predicates.
 */

/** Gets `template` with `{0}` replaced by `a`. */
bindingset[template, a]
string fmt(string template, string a) { result = template.replaceAll("{0}", a) }

/** Gets `template` with `{0}` and `{1}` replaced by `a` and `b`. */
bindingset[template, a, b]
string fmt(string template, string a, string b) {
  result = template.replaceAll("{0}", a).replaceAll("{1}", b)
}

/** Gets `template` with `{0}` .. `{2}` replaced. */
bindingset[template, a, b, c]
string fmt(string template, string a, string b, string c) {
  result = template.replaceAll("{0}", a).replaceAll("{1}", b).replaceAll("{2}", c)
}
