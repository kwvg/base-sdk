/**
 * Copyright (c) 2026-present, The Dash Core developers
 * SPDX-License-Identifier: MIT
 * See the accompanying file LICENSE or https://opensource.org/license/MIT
 *
 * @description Rule-specific policy predicates for type classification.
 */

import lib.files
import lib.filters
import lib.traits
import rust

/** Holds if `t` carries `#[derive(Unencodable)]` or `#[derive(dash_types::Unencodable)]`. */
predicate isNotEncodable(TypeItem t) {
  exists(Attr a |
    a = t.getAnAttr() and
    a.getMeta().getPath().getSegment().getIdentifier().getText() = "derive" and
    a.getMeta().getTokenTree().toAbbreviatedString().regexpMatch(".*\\bUnencodable\\b.*")
  )
}

/** Holds if `t` holds secret or security-sensitive material. */
predicate isSecretType(TypeItem t) {
  t.getName().getText().regexpMatch(".*(Secret|Private|Seed|Password|Mnemonic|Share).*") and
  // Exclude types whose name contains "Shared" (e.g. SharedState),
  // which match the Share substring but are not secret holders.
  not t.getName().getText().regexpMatch(".*Shared.*")
}

/** Holds if `t` is an iterator type (name ends with Iterator or Iter). */
predicate isIteratorType(TypeItem t) {
  t.getName().getText().matches("%Iterator") or
  t.getName().getText().matches("%Iter")
}

/** Holds if `t` is an error type (name ends with Error, Invalid, TooLong, or TooShort). */
predicate isErrorType(TypeItem t) {
  t.getName().getText().matches("%Error") or
  t.getName().getText().matches("%Invalid") or
  t.getName().getText().matches("%TooLong") or
  t.getName().getText().matches("%TooShort")
}

/** Holds if `t` is a dispatch/message type (name ends with Message). */
predicate isDispatchType(TypeItem t) { t.getName().getText().matches("%Message") }

/** Holds if `t` is an opaque single-field wrapper in the pkc crate. */
predicate isOpaqueType(TypeItem t) {
  t instanceof Struct and
  exists(string path |
    path = fileOf(t).getAbsolutePath() and
    path.matches("%/pkgs/pkc/%")
  ) and
  isSingleTupleField(t)
}

/** Holds if struct `s` contains a float field, directly or transitively. */
predicate hasFloatField(TypeItem t) {
  typeFieldName(t) = ["f32", "f64"]
  or
  exists(TypeItem inner |
    inner.getName().getText() = typeFieldName(t) and
    cratePrefix(inner) = cratePrefix(t) and
    hasFloatField(inner)
  )
}
