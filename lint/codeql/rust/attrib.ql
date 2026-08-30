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

import lib.filters
import lib.fmt
import lib.policy
import lib.traits
import rust

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

/** Holds if `t` has TypeId coverage */
predicate hasTypeId(TypeItem t) {
  implementsTrait(t, "TypeId") or
  hasDerive(t, "TypeId")
}

from TypeItem t, string message
where
  isCheckableType(t) and
  (
    exists(string missing |
      missing = missingTraits(t) and
      message = fmt("missing required derivations: {0}", missing)
    )
    or
    // Serde: every non-exempt type must derive Serialize + Deserialize.
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
    or
    // Codec coverage: every type in a crate with Hashable + Unencodable must be
    // wire (Hashable + TypeId) or non-wire (Unencodable). Lower-level crates
    // (e.g. dash-num) lack these traits and are exempt.
    isUnencodableCrate(fileOf(t)) and
    not isErrorType(t) and
    not isIteratorType(t) and
    (
      // No coverage at all: neither wire traits nor Unencodable.
      not implementsTrait(t, "BaseCodec") and
      not isNotEncodable(t) and
      message =
        "missing codec coverage: implement Hashable + TypeId (wire) or derive Unencodable (non-wire)"
      or
      // Wire type (has BaseCodec) but missing required codec traits.
      implementsTrait(t, "BaseCodec") and
      not isNotEncodable(t) and
      exists(string missing |
        missing =
          concat(string trait |
            (trait = "Hashable" or trait = "TypeId") and
            not (trait = "TypeId" and hasTypeId(t)) and
            not (trait = "Hashable" and implementsTrait(t, "Hashable"))
          |
            trait, ", " order by trait
          ) and
        missing != "" and
        message = fmt("wire type (BaseCodec) missing codec traits: {0}", missing)
      )
      or
      // Conflict: wire type incorrectly marked Unencodable.
      implementsTrait(t, "BaseCodec") and
      isNotEncodable(t) and
      message =
        "conflicting codec marker: type has BaseCodec but derives Unencodable; implement Hashable + TypeId instead"
    )
  )
select t, message
