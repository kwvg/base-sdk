/**
 * Copyright (c) 2026-present, The Dash Core developers
 * SPDX-License-Identifier: MIT
 * See the accompanying file LICENSE or https://opensource.org/license/MIT
 *
 * @id base-sdk/zeroize-rules
 * @name Secret material handling rules
 * @description Secret types must wipe, redact, and stay off growable buffers.
 * @kind problem
 * @precision high
 * @problem.severity error
 * @tags security
 */

import lib.files
import lib.filters
import lib.fmt
import lib.policy
import lib.traits
import lib.types
import rust

/**
 * Holds if `f` erases something, as a method call or a qualified path call.
 *
 * Matched on the `zeroize` prefix: `<Self as Zeroize>::zeroize(self)` is the
 * spelling a manual `Drop` needs to reach the trait method, and a backend
 * wipes through its own helper.
 */
predicate callsZeroize(Function f) {
  exists(MethodCallExpr mc |
    mc.getEnclosingCallable() = f and
    mc.getIdentifier().getText().matches("zeroize%")
  )
  or
  exists(PathExpr pe |
    pe.getEnclosingCallable() = f and
    pe.getPath().getSegment().getIdentifier().getText().matches("zeroize%")
  )
}

/**
 * Holds if `t` wipes its own storage.
 *
 * A bare `Drop` impl proves nothing on its own, so the body has to be seen
 * erasing something before the type counts as wiped.
 */
predicate wipesSelf(TypeItem t) {
  isWorkspaceFile(fileOf(t)) and
  (
    implementsTrait(t, ["Zeroize", "ZeroizeOnDrop"]) or
    hasDerive(t, ["Zeroize", "ZeroizeOnDrop"])
  )
  or
  exists(Impl i, Function d |
    i.getSelf() = t and
    implTraitName(i) = "Drop" and
    isWorkspaceFile(fileOf(i)) and
    d = i.getAssocItemList().getAnAssocItem() and
    d.getName().getText() = "drop" and
    callsZeroize(d)
  )
}

/**
 * Holds if the dependency type `t` erases itself on drop.
 *
 * Enumerated because the extractor keeps dependency function bodies out of
 * the database.
 */
predicate externalWiper(TypeItem t) {
  not isWorkspaceFile(fileOf(t)) and
  (
    // `k256::ecdsa::SigningKey` derives `ZeroizeOnDrop`.
    t.getName().getText() = "SigningKey" and
    fileOf(t).getAbsolutePath().matches("%/ecdsa-%/src/signing.rs")
    or
    // `blst::{min_pk,min_sig}::SecretKey` are declared `#[zeroize(drop)]`.
    t.getName().getText() = "SecretKey" and
    fileOf(t).getAbsolutePath().matches("%/blst-%/src/lib.rs")
  )
}

/** Holds if `t` erases its own storage, without delegating to a field. */
predicate wipesDirectly(TypeItem t) {
  wipesSelf(t)
  or
  externalWiper(t)
}

/**
 * Holds if a field written as `tr` may be holding secret material.
 */
predicate fieldMayHoldSecret(TypeRepr tr) {
  isSecretType(namedTypeItem(tr))
  or
  isGrowableType(tr)
  or
  tr instanceof ArrayTypeRepr
}

/**
 * Holds if a field written as `tr` keeps secret material nothing erases.
 *
 * Recursive, so a field that neither wipes itself nor sits inside `Zeroizing`
 * is cleared only when everything it is in turn built from is cleared. A field
 * whose type has no fields to descend into has nowhere left to delegate, so it
 * stays reported.
 */
predicate fieldNotWiped(TypeRepr tr) {
  fieldMayHoldSecret(tr) and
  not typeHead(tr) = "Zeroizing" and
  not wipesDirectly(namedTypeItem(tr)) and
  (
    not exists(fieldTypeRepr(namedTypeItem(tr)))
    or
    fieldNotWiped(fieldTypeRepr(namedTypeItem(tr)))
  )
}

/**
 * Holds if every field of `t` is wiped or holds no secret, at any depth.
 *
 * Checked per field: one wrapped field says nothing about its siblings.
 */
predicate fieldsWipe(TypeItem t) {
  exists(fieldTypeRepr(t)) and
  not fieldNotWiped(fieldTypeRepr(t))
}

/**
 * Holds if the secret material in `t` is wiped by something.
 *
 * Either `t` erases itself, or every secret-bearing field it holds is wiped,
 * recursively.
 */
predicate zeroizeSatisfied(TypeItem t) {
  wipesDirectly(t)
  or
  fieldsWipe(t)
}

/**
 * Holds if `t` reaches the wire through the wiping encoder pair.
 *
 * `impl_stype!`/`impl_sbytes!` emit `type Encoder = ArrEncoder<N>`; the plain
 * `impl_type!`/`impl_bytes!` emit `type Encoder = VecEncoder`.
 */
predicate usesSecretBridge(TypeItem t) {
  exists(Impl i, TypeAlias ta |
    i.getSelf() = t and
    implTraitName(i) = "Encodable" and
    ta = i.getAssocItemList().getAnAssocItem() and
    ta.getName().getText() = "Encoder" and
    typeHead(ta.getTypeRepr()) = "ArrEncoder"
  )
}

/** Holds if `f` stages secret material through a wiping wrapper. */
predicate wipesInBody(Function f) {
  callsZeroize(f)
  or
  exists(PathExpr pe, Path p |
    pe.getEnclosingCallable() = f and
    p = pe.getPath() and
    p.getSegment().getIdentifier().getText() = "new" and
    p.getQualifier().getSegment().getIdentifier().getText() = "Zeroizing"
  )
}

/**
 * Holds if `f` hands back a bare byte container.
 *
 * A `Zeroizing<..>` return is the wanted shape and a reference borrows rather
 * than copies, so neither is reported.
 */
predicate returnsBareBytes(Function f, string retType) {
  exists(TypeRepr tr |
    tr = f.getRetType().getTypeRepr() and
    (
      tr instanceof ArrayTypeRepr and
      typeHead(tr.(ArrayTypeRepr).getElementTypeRepr()) = "u8" and
      retType = "[u8; N]"
      or
      typeHead(tr) = ["Vec", "String"] and retType = typeHead(tr)
    )
  )
}

/**
 * Holds if `t` decides equality with `subtle`'s constant-time comparison.
 *
 * A derived `PartialEq` compares field by field and returns at the first
 * mismatch, so how long a comparison runs reveals how much of the secret the
 * caller already guessed.
 */
predicate constantTimeEq(TypeItem t) {
  exists(Impl i, Function eq |
    i.getSelf() = t and
    implTraitName(i) = "PartialEq" and
    eq = i.getAssocItemList().getAnAssocItem() and
    eq.getName().getText() = "eq" and
    callsCtEq(eq)
  )
}

/** Holds if `f` compares through `subtle`. */
predicate callsCtEq(Function f) {
  exists(MethodCallExpr mc |
    mc.getEnclosingCallable() = f and
    mc.getIdentifier().getText() = "ct_eq"
  )
}

/**
 * Holds if `e` reads byte storage rather than an opaque value.
 *
 * Fields are judged by their declared type, resolved through the type layer, so
 * a flag sitting beside the bytes is not mistaken for them. References and
 * derefs are looked through.
 */
predicate bytesExpr(Expr e) {
  e instanceof ArrayExpr
  or
  e.(MethodCallExpr).getIdentifier().getText() =
    ["as_bytes", "as_ref", "as_slice", "to_bytes", "into_bytes", "as_array", "expose_secret"]
  or
  fieldMayHoldSecret(e.(FieldExpr).getStructField().getTypeRepr())
  or
  fieldMayHoldSecret(e.(FieldExpr).getTupleField().getTypeRepr())
  or
  bytesExpr(e.(RefExpr).getExpr())
  or
  bytesExpr(e.(PrefixExpr).getExpr())
}

/**
 * Holds if `f` compares byte storage with `how`, an operator that stops early.
 *
 * `==` on bytes compiles to `memcmp`, which short-circuits on the first
 * mismatch. The operand gate keeps the rule on byte storage, so deciding on
 * a flag, a length, or an enum discriminant beside the secret is not
 * reported. Secrecy itself is not judged here: `variableTimeSecretTest`
 * supplies that through `enforcedSecretType`.
 */
predicate comparesBytes(Function f, string how) {
  exists(BinaryExpr be |
    be.getEnclosingCallable() = f and
    be.getOperatorName() = ["==", "!="] and
    bytesExpr([be.getLhs(), be.getRhs()]) and
    how = be.getOperatorName()
  )
}

/**
 * Holds if `f` decides something with a short-circuiting adapter, named `how`.
 *
 * These walk only as far as the first byte that settles the answer.
 */
predicate stopsEarly(Function f, string how) {
  exists(MethodCallExpr mc, string name |
    mc.getEnclosingCallable() = f and
    name = mc.getIdentifier().getText() and
    name = ["all", "any", "position", "find", "contains", "starts_with", "ends_with"] and
    how = name + "()"
  )
}

/**
 * Holds if a method of a secret type answers a yes/no question about its own
 * bytes in variable time, because it uses `how`.
 *
 * `PartialEq` has its own rule, so `eq` is left to it. This covers the
 * predicates that sit beside it, e.g. an `is_null` that returns at the first
 * non-zero byte and so leaks how long the leading run of zeroes is.
 */
predicate variableTimeSecretTest(Function f, string how) {
  exists(TypeItem t, Impl i |
    enforcedSecretType(t) and
    i.getSelf() = t and
    f = i.getAssocItemList().getAnAssocItem() and
    not isTestCode(f) and
    not f.getName().getText() = "eq" and
    typeHead(f.getRetType().getTypeRepr()) = "bool" and
    (
      stopsEarly(f, how)
      or
      comparesBytes(f, how)
    ) and
    not callsCtEq(f)
  )
}

/**
 * Holds if `t` is a secret-bearing type.
 *
 * Unlike `isSourceType` this preserves macro-generated items: `make_bytes!` and
 * friends can mint secret bags wholesale, and dropping them would leave the types
 * this query exists to examine unchecked.
 */
predicate secretType(TypeItem t) {
  (isSecretType(t) or wipesSelf(t)) and
  fileOf(t).fromSource() and
  not isTestCode(t)
}

/** Holds if `t` is a secret-bearing type in a crate the policy covers. */
predicate enforcedSecretType(TypeItem t) {
  secretType(t) and
  isEnforcedCrate(fileOf(t))
}

/** Holds if the secret material in `t` is never erased. */
predicate unwipedSecret(TypeItem t) {
  enforcedSecretType(t) and
  not zeroizeSatisfied(t)
}

/** Holds if `t` can be formatted without redacting its contents, because `cause`. */
predicate unredactedSecret(TypeItem t, string cause) {
  enforcedSecretType(t) and
  (
    hasDerivedImpl(t, "Debug") and cause = "derives Debug"
    or
    hasDerivedImpl(t, "Display") and cause = "derives Display"
    or
    not implementsTrait(t, "Debug") and cause = "has no manual Debug"
  )
}

/**
 * Holds if `f` wipes internally but hands the caller a bare `retType`, leaving
 * the erasure of that copy to them.
 */
predicate leakedWipedBytes(Function f, string retType) {
  isEnforcedCrate(fileOf(f)) and
  not isTestCode(f) and
  wipesInBody(f) and
  returnsBareBytes(f, retType)
}

/**
 * Holds if `t` is an encodable secret on growable storage, which can
 * reallocate mid-write and strand a copy the wipe never reaches.
 */
predicate growableSecret(TypeItem t) {
  enforcedSecretType(t) and
  not isNotEncodable(t) and
  isGrowableType(fieldTypeRepr(t))
}

/** Holds if `t` reaches the wire through an encoder that does not wipe. */
predicate leakySecretBridge(TypeItem t) {
  enforcedSecretType(t) and
  implementsTrait(t, "Encodable") and
  not usesSecretBridge(t)
}

/** Holds if `t` can be compared in a time that depends on its contents. */
predicate variableTimeSecretEq(TypeItem t) {
  enforcedSecretType(t) and
  implementsTrait(t, "PartialEq") and
  not constantTimeEq(t)
}

from Locatable e, string message
where
  unwipedSecret(e) and message = "secret type is never wiped"
  or
  exists(string cause | unredactedSecret(e, cause) | message = fmt("secret type {0}", cause))
  or
  exists(string retType | leakedWipedBytes(e, retType) |
    message = fmt("wiping function returns bare {0}", retType)
  )
  or
  growableSecret(e) and message = "encodable secret type is backed by a growable buffer"
  or
  leakySecretBridge(e) and message = "secret wire type stages through a non-wiping encoder"
  or
  variableTimeSecretEq(e) and message = "secret type compares in variable time"
  or
  exists(string how | variableTimeSecretTest(e, how) |
    message = fmt("secret type test uses {0}, which stops early", how)
  )
select e, message
