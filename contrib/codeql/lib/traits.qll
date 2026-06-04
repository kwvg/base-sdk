/**
 * Copyright (c) 2026-present, The Dash Core developers
 * SPDX-License-Identifier: MIT
 * See the accompanying file LICENSE or https://opensource.org/license/MIT
 *
 * @description Helpers for inspecting trait impls and derive macros.
 */

import lib.files
import rust

/** Gets the trait name from an impl block's trait reference. */
string implTraitName(Impl i) {
  result = i.getTrait().(PathTypeRepr).getPath().getSegment().getIdentifier().getText()
}

/** Holds if `t` has a derived impl for `traitName`. */
predicate hasDerivedImpl(TypeItem t, string traitName) {
  exists(MacroItems expansion, Impl i |
    expansion = t.getADeriveMacroExpansion() and
    i = expansion.getItem(_) and
    implTraitName(i) = traitName
  )
}
