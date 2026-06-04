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
    fileOf(i) = fileOf(t) and
    implSelfName(i) = t.getName().getText() and
    implTraitName(i) = traitName and
    not exists(MacroItems m | i = m.getItem(_))
  )
}

/** Holds if `t` has a macro-generated (non-derive) impl for `traitName`. */
predicate hasMacroImpl(TypeItem t, string traitName) {
  exists(MacroItems m, Impl i |
    i = m.getItem(_) and
    not m = t.getADeriveMacroExpansion() and
    fileOf(i) = fileOf(t) and
    implSelfName(i) = t.getName().getText() and
    implTraitName(i) = traitName
  )
}

/** Holds if `t` implements `traitName` via derive, manual impl, or macro. */
predicate implementsTrait(TypeItem t, string traitName) {
  hasDerivedImpl(t, traitName) or
  hasManualImpl(t, traitName) or
  hasMacroImpl(t, traitName)
}

/**
 * Holds if `t` has a derived impl for `traitName` under `crate`
 * (i.e. the trait path is `::<crate>::<traitName>`).
 */
predicate hasDerivedImplInCrate(TypeItem t, string traitName, string crate) {
  exists(MacroItems expansion, Impl i, Path p |
    expansion = t.getADeriveMacroExpansion() and
    i = expansion.getItem(_) and
    p = i.getTrait().(PathTypeRepr).getPath() and
    p.getSegment().getIdentifier().getText() = traitName and
    p.getQualifier().getSegment().getIdentifier().getText() = crate
  )
}

/**
 * Holds if `t` has a manual impl for `traitName` under `crate`
 * (i.e. the trait path is `<crate>::<traitName>`).
 */
predicate hasManualImplInCrate(TypeItem t, string traitName, string crate) {
  exists(Impl i, Path p |
    fileOf(i) = fileOf(t) and
    implSelfName(i) = t.getName().getText() and
    not exists(MacroItems m | i = m.getItem(_)) and
    p = i.getTrait().(PathTypeRepr).getPath() and
    p.getSegment().getIdentifier().getText() = traitName and
    p.getQualifier().getSegment().getIdentifier().getText() = crate
  )
}

/**
 * Holds if `t` has a macro-generated (non-derive) impl for `traitName`
 * under `crate` (e.g. from `impl_num!`).
 */
predicate hasMacroImplInCrate(TypeItem t, string traitName, string crate) {
  exists(MacroItems m, Impl i, Path p |
    i = m.getItem(_) and
    not m = t.getADeriveMacroExpansion() and
    fileOf(i) = fileOf(t) and
    implSelfName(i) = t.getName().getText() and
    p = i.getTrait().(PathTypeRepr).getPath() and
    p.getSegment().getIdentifier().getText() = traitName and
    p.getQualifier().getSegment().getIdentifier().getText() = crate
  )
}

/**
 * Holds if `t` implements `traitName` under `crate` via derive,
 * manual impl, or non-derive macro expansion.
 */
predicate implementsTraitInCrate(TypeItem t, string traitName, string crate) {
  hasDerivedImplInCrate(t, traitName, crate) or
  hasManualImplInCrate(t, traitName, crate) or
  hasMacroImplInCrate(t, traitName, crate)
}

/**
 * Holds if `t` has a `cfg_attr`-wrapped derive that mentions
 * `traitName` gated on `feature` under `crate`.
 *
 * `getADeriveMacroExpansion()` does not trace through `cfg_attr`,
 * so we fall back to inspecting the attribute text.
 */
bindingset[traitName, feature, crate]
predicate hasCfgAttrDeriveInSource(TypeItem t, string traitName, string feature, string crate) {
  exists(Attr a, string text |
    a = t.getAnAttr() and
    a.getMeta().getPath().getSegment().getIdentifier().getText() = "cfg_attr" and
    text = a.getMeta().getTokenTree().toAbbreviatedString() and
    text.matches("%" + feature + "%") and
    text.matches("%derive%") and
    text.matches("%" + crate + "%") and
    text.matches("%" + traitName + "%")
  )
}

/** Gets the line of a hand-written `impl Trait for name` in file `f`. */
int traitImplLine(File f, string name, string trait) {
  exists(Impl i |
    not exists(MacroItems m | i = m.getItem(_)) and
    fileOf(i) = f and
    implSelfName(i) = name and
    implTraitName(i) = trait and
    result = startLine(i)
  )
}

/** Gets the line of an inherent impl (no trait) for `name` in file `f`. */
int inherentImplLine(File f, string name) {
  exists(Impl i |
    not exists(MacroItems m | i = m.getItem(_)) and
    fileOf(i) = f and
    implSelfName(i) = name and
    not exists(implTraitName(i)) and
    result = startLine(i)
  )
}
