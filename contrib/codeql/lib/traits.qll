/**
 * Copyright (c) 2026-present, The Dash Core developers
 * SPDX-License-Identifier: MIT
 * See the accompanying file LICENSE or https://opensource.org/license/MIT
 *
 * Helpers for inspecting trait implementations and derive macros.
 */

import rust

/** Gets the trait name from an impl block's trait reference. */
string implTraitName(Impl i) {
  result = i.getTrait().(PathTypeRepr).getPath().getSegment().getIdentifier().getText()
}

/** Gets the type name from an impl block's self type. */
string implSelfName(Impl i) {
  result = i.getSelfTy().(PathTypeRepr).getPath().getSegment().getIdentifier().getText()
}

/** Holds if `t` has a derived impl for `traitName`. */
predicate hasDerivedImpl(TypeItem t, string traitName) {
  exists(MacroItems expansion, Impl i |
    expansion = t.getADeriveMacroExpansion() and
    i = expansion.getItem(_) and
    implTraitName(i) = traitName
  )
}

/** Holds if `t` has a manual impl for `traitName`. */
predicate hasManualImpl(TypeItem t, string traitName) {
  exists(Impl i |
    i.getLocation().getFile() = t.getLocation().getFile() and
    implSelfName(i) = t.getName().getText() and
    implTraitName(i) = traitName and
    not exists(MacroItems m | i = m.getItem(_))
  )
}

/** Holds if `t` implements `traitName` via derive or manual impl. */
predicate implementsTrait(TypeItem t, string traitName) {
  hasDerivedImpl(t, traitName) or hasManualImpl(t, traitName)
}

/**
 * Holds if `t` has a derived impl for `traitName` under the `serde` crate
 * (i.e. the trait path is `::serde::<traitName>`).
 */
predicate hasSerdeDerivedImpl(TypeItem t, string traitName) {
  exists(MacroItems expansion, Impl i, Path p |
    expansion = t.getADeriveMacroExpansion() and
    i = expansion.getItem(_) and
    p = i.getTrait().(PathTypeRepr).getPath() and
    p.getSegment().getIdentifier().getText() = traitName and
    p.getQualifier().getSegment().getIdentifier().getText() = "serde"
  )
}

/**
 * Holds if `t` implements a serde trait via derive or manual impl.
 * Checks both `::serde::`-qualified derives and manual impls.
 */
predicate implementsSerdeTrait(TypeItem t, string traitName) {
  hasSerdeDerivedImpl(t, traitName) or hasManualImpl(t, traitName)
}
