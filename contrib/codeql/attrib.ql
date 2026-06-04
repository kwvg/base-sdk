/**
 * Copyright (c) 2026-present, The Dash Core developers
 * SPDX-License-Identifier: MIT
 * See the accompanying file LICENSE or https://opensource.org/license/MIT
 *
 * @name Attribute and derivation rules
 * @description Enforcement of required traits per feasible type.
 * @kind problem
 * @problem.severity warning
 * @id base-sdk/attrib-rules
 * @tags style
 * @precision high
 */

import lib.files
import lib.filters
import lib.fmt
import lib.traits
import rust

/** Gets a required trait name. */
string requiredTrait() { result = ["Clone", "Debug", "Eq", "Hash", "PartialEq"] }

/** Gets a required serde trait name. */
string requiredSerdeTrait() { result = ["Serialize", "Deserialize"] }

/** Holds if `t` is codec infrastructure (decoder or encoder wrappers). */
predicate isCodecType(TypeItem t) {
  t.getName().getText().matches("%Decoder%") or
  t.getName().getText().matches("%Encoder%")
}

/** Holds if `t` is a source type eligible for the "must derive" check. */
predicate isCheckableType(TypeItem t) {
  isSourceType(t) and
  not isCodecType(t) and
  not isSecretType(t) and
  not isIteratorType(t)
}

/** Holds if `t` lives in a crate that does not have a `serde` feature. */
predicate isNonSerdeCrate(TypeItem t) {
  exists(string path |
    path = fileOf(t).getAbsolutePath() and
    (path.matches("%/pkgs/params/%") or path.matches("%/pkgs/pow/%"))
  )
}

/**
 * Holds when `trait` should not be required for `t`.
 */
predicate isSuppressed(TypeItem t, string trait) {
  // Float types: suppress Eq and Hash
  hasFloatField(t) and trait = ["Eq", "Hash"]
  or
  // Error types: suppress Hash
  isErrorType(t) and trait = "Hash"
  or
  // Dispatch types: suppress Hash
  isDispatchType(t) and trait = "Hash"
  or
  // Opaque types: suppress Hash
  isOpaqueType(t) and trait = "Hash"
}

/** Holds if `t` is exempt from serde derivation requirements. */
predicate isSerdeExempt(TypeItem t) {
  isNonSerdeCrate(t)
  or
  isNotEncodable(t)
  or
  isCodecType(t)
  or
  isErrorType(t)
  or
  isDispatchType(t)
  or
  hasLifetime(t)
  or
  // Single-field wrappers without PartialEq are exempt.
  isSingleTupleField(t) and
  not implementsTrait(t, "PartialEq")
}

/** Gets a comma-separated list of missing required traits for `t`. */
string missingTraits(TypeItem t) {
  isCheckableType(t) and
  result =
    concat(string trait |
      trait = requiredTrait() and
      not implementsTrait(t, trait) and
      not isSuppressed(t, trait)
    |
      trait, ", " order by trait
    ) and
  result != ""
}

from TypeItem t, string message
where
  (
    isCheckableType(t) and
    exists(string missing |
      missing = missingTraits(t) and
      message = fmt("missing required derivations: {0}", missing)
    )
    or
    // Serde: every non-exempt type must derive Serialize + Deserialize.
    isCheckableType(t) and
    not isSerdeExempt(t) and
    exists(string missing |
      missing =
        concat(string trait |
          trait = requiredSerdeTrait() and
          not implementsSerdeTrait(t, trait)
        |
          trait, ", " order by trait
        ) and
      missing != "" and
      message = fmt("missing serde derivations: {0}", missing)
    )
  )
select t, message
