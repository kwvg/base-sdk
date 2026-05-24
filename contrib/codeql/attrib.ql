/**
 * @name Attribute and derivation rules
 * @description Derivation rules: required traits and secret-type restrictions.
 * @kind problem
 * @problem.severity warning
 * @id base-sdk/attrib-rules
 * @tags style
 * @precision high
 */

import lib.filters
import lib.fmt
import lib.traits
import rust

/** Gets a required trait name. */
string requiredTrait() { result = ["Clone", "Debug", "PartialEq", "Eq"] }

/** Gets a required serde trait name. */
string requiredSerdeTrait() { result = ["Serialize", "Deserialize"] }

/** Holds if `t` is codec infrastructure (decoder or encoder wrappers). */
predicate isCodecType(TypeItem t) {
  t.getName().getText().matches("%Decoder%") or
  t.getName().getText().matches("%Encoder%")
}

/** Holds if `t` is an error or validation-failure type. */
predicate isErrorType(TypeItem t) {
  t.getName().getText().matches("%Error") or
  t.getName().getText().matches("%Invalid") or
  t.getName().getText().matches("%TooLong") or
  t.getName().getText().matches("%TooShort")
}

/** Holds if `t` holds secret or security-sensitive material. */
predicate isSecretType(TypeItem t) {
  t.getName().getText().regexpMatch(".*(Secret|Private|Seed|Password|Mnemonic|Share).*")
}

/** Holds if `t` lives in a crate that does not have a `serde` feature. */
predicate isNonSerdeCrate(TypeItem t) {
  exists(string path |
    path = t.getLocation().getFile().getAbsolutePath() and
    (path.matches("%/pkgs/params/%") or path.matches("%/pkgs/pow/%"))
  )
}

/** Holds if `t` is a source type eligible for the "must derive" check. */
predicate isCheckableType(TypeItem t) {
  (t instanceof Struct or t instanceof Enum or t instanceof Union) and
  t.getLocation().getFile().fromSource() and
  not isTestCode(t) and
  not isMacroGenerated(t) and
  not isLocalType(t) and
  not isCodecType(t) and
  not isSecretType(t)
}

/** Holds if `t` is a source type eligible for any check. */
predicate isSourceType(TypeItem t) {
  (t instanceof Struct or t instanceof Enum or t instanceof Union) and
  t.getLocation().getFile().fromSource() and
  not isTestCode(t) and
  not isMacroGenerated(t) and
  not isLocalType(t)
}

/**
 * Holds when `trait` should not be required for `t`.
 * Eq is suppressed for structs that transitively contain a float field.
 */
predicate isSuppressed(TypeItem t, string trait) { trait = "Eq" and hasFloatField(t) }

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
    isSourceType(t) and
    isSecretType(t) and
    hasDerivedImpl(t, "Debug") and
    message = "secret type must not derive Debug; use a custom impl that redacts content"
    or
    isCheckableType(t) and
    not isNonSerdeCrate(t) and
    not isErrorType(t) and
    not isOpaqueWrapper(t) and
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
