/**
 * Copyright (c) 2026-present, The Dash Core developers
 * SPDX-License-Identifier: MIT
 * See the accompanying file LICENSE or https://opensource.org/license/MIT
 *
 * @description Rule-specific policy predicates for type classification.
 */

import lib.files
import lib.filters
import lib.source_lines
import lib.traits
import lib.types
import rust

/** Holds if `t` carries `#[derive(...name...)]` detected via source-line scanning. */
bindingset[name]
predicate hasDerive(TypeItem t, string name) {
  exists(Attr a, int srcLine, string relPath, string content |
    a = t.getAnAttr() and
    (
      a.getMeta().getPath().getText() = "derive" or
      a.getMeta().getPath().getText() = "cfg_attr"
    ) and
    fileRelPath(fileOf(t), relPath) and
    sourceLineContent(relPath, srcLine, content) and
    content.regexpMatch(".*\\b" + name + "\\b.*") and
    srcLine >= a.getLocation().getStartLine() and
    srcLine <= a.getLocation().getEndLine()
  )
}

/** Holds if `t` is a non-wire type (Unencodable derive, or has __CodecMarker w/o Hashable). */
predicate isNotEncodable(TypeItem t) {
  hasDerive(t, "Unencodable")
  or
  implementsTrait(t, "__CodecMarker") and
  not implementsTrait(t, "Hashable")
}

/** Holds if `t` holds secret or security-sensitive material. */
predicate isSecretType(TypeItem t) {
  (
    t.getName().getText().regexpMatch(".*(Secret|Private|Seed|Password|Mnemonic|SkBytes|DhBytes).*")
    or
    // "Share" is the one keyword that "Shared" (e.g. SharedState) matches without holding a secret,
    // so the guard applies to it alone, exceptions to this rule are explicitly enumerated.
    t.getName().getText().regexpMatch(".*Share.*") and
    not t.getName().getText().regexpMatch(".*Shared.*")
    or
    // Scalar field wrapper holding secret key material
    t.getName().getText() = "Fr"
  ) and
  not t.getName().getText() =
    [
      // A share *of a signature* is published, so it's non-secret. Excluded by exact name because
      // `BlsSkShare` and `RawShare` match the same Share substring and do carry secret scalars.
      "BlsSigShare",
      // The identifier a share is issued against is the participant's, known to every member of the
      // quorum; only the scalar the share carries is secret.
      "BlsShareId",
      // Serde artifact to deserialize a tagged enum.
      "__Seed"
    ]
}

/**
 * Holds if `tr` names a heap-growable container.
 *
 * A `Vec` or `String` can reallocate while being filled, stranding a copy at
 * the old allocation that drop-time wiping cannot reach.
 */
predicate isGrowableType(TypeRepr tr) {
  typeHead(tr) = ["Vec", "String", "VecDeque", "BTreeMap", "BTreeSet", "BinaryHeap"]
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

/** Holds if `t` is a compile-time marker type (empty enum, zero-sized). */
predicate isMarkerType(TypeItem t) {
  t instanceof Enum and
  t.(Enum).hasVariantList() and
  count(t.(Enum).getVariantList().getAVariant()) = 0
}

/** Materialises (TypeItem, fieldTypeName, crate) for join efficiency. */
pragma[nomagic]
private predicate fieldTypeInCrate(TypeItem t, string fieldTypeName, string crate) {
  fieldTypeName = typeFieldName(t) and crate = cratePrefix(t)
}

/** Materialises (TypeItem, name, crate) for join efficiency. */
pragma[nomagic]
private predicate typeNameInCrate(TypeItem t, string name, string crate) {
  name = t.getName().getText() and crate = cratePrefix(t)
}

/** Holds if struct `s` contains a float field, directly or transitively. */
predicate hasFloatField(TypeItem t) {
  typeFieldName(t) = ["f32", "f64"]
  or
  exists(TypeItem inner, string name, string crate |
    fieldTypeInCrate(t, name, crate) and
    typeNameInCrate(inner, name, crate) and
    hasFloatField(inner)
  )
}

/**
 * Holds if `t` is a serde internal generated type
 * (e.g. __FieldVisitor, __Visitor, __Field).
 */
predicate isSerdeInternalType(TypeItem t) { t.getName().getText().matches("\\_\\_%") }

/** Gets a required trait name. */
string requiredTrait() { result = ["Clone", "Debug", "Eq", "Hash", "PartialEq"] }

/** Gets a required serde trait name. */
string requiredSerdeTrait() { result = ["Serialize", "Deserialize"] }

/** Holds if `t` is codec infrastructure (decoder, encoder, or buffer types). */
predicate isCodecType(TypeItem t) {
  t.getName().getText().matches("%Decoder%") or
  t.getName().getText().matches("%Encoder%") or
  t.getName().getText() = "ArrayBuf"
}

/** Holds if `name` is a trait whose methods must have a body in exactly one layer. */
predicate isMutexTrait(string name) { name = "BlsScheme" }

/** Holds if `t` lives in a crate with no public API. */
predicate isPrivateCrate(TypeItem t) {
  exists(string path |
    path = fileOf(t).getAbsolutePath() and
    path.matches("%/pkgs/dev/%")
  )
}

/** Holds if `t` is a source type eligible for the "must derive" check. */
predicate isCheckableType(TypeItem t) {
  isSourceType(t) and
  not isSerdeInternalType(t) and
  not isCodecType(t) and
  not isSecretType(t) and
  not isIteratorType(t) and
  not isPrivateCrate(t) and
  not hasUnexpandedDerive(t)
}

/** Holds if `t` lives in a crate that does not have a `serde` feature. */
predicate isNonSerdeCrate(TypeItem t) {
  exists(string path |
    path = fileOf(t).getAbsolutePath() and
    (path.matches("%/pkgs/params/%") or path.matches("%/pkgs/pow/%"))
  )
}

/**
 * Holds if `t` implements a serde trait via crate-qualified impl,
 * unqualified proc-macro expansion, or source-scanned match.
 */
bindingset[traitName]
predicate implementsSerdeTrait(TypeItem t, string traitName) {
  implementsTraitInCrate(t, traitName, "serde")
  or
  // Serde proc-macro derives may emit unqualified impls that
  // escape MacroItems wrapping.  Detect them by requiring the
  // impl location to fall inside the type definition span (a
  // hand-written impl is always outside that span).
  (traitName = "Serialize" or traitName = "Deserialize") and
  exists(Impl i |
    not exists(MacroItems m | i = m.getItem(_)) and
    fileOf(i) = fileOf(t) and
    implSelfName(i) = t.getName().getText() and
    implTraitName(i) = traitName and
    startLine(i) >= startLine(t) and
    startLine(i) <= endLine(t)
  )
  or
  // Derive mention inside an attribute range (cfg_attr, cfg, or derive).
  exists(Attr a, int srcLine, string relPath, string content |
    a = t.getAnAttr() and
    fileRelPath(fileOf(t), relPath) and
    sourceLineContent(relPath, srcLine, content) and
    content.regexpMatch(".*\\b" + traitName + "\\b.*") and
    srcLine >= a.getLocation().getStartLine() and
    srcLine <= a.getLocation().getEndLine()
  )
  or
  // Manual impl behind #[cfg(feature = "serde")] that the
  // extractor cannot see.
  exists(string relPath, string content |
    fileRelPath(fileOf(t), relPath) and
    sourceLineContent(relPath, _, content) and
    content
        .regexpMatch("impl\\b.*\\bserde::" + traitName + "\\b.*\\bfor\\s+" + t.getName().getText() +
            "\\b.*")
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
  or
  // Projective point wrappers hold non-canonical coordinates: suppress Eq and PartialEq
  isOpaqueType(t) and
  t.getName().getText() = ["G1", "G2"] and
  trait = ["Eq", "PartialEq"]
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
  isOpaqueType(t)
  or
  isMarkerType(t)
  or
  hasLifetime(t)
  or
  // Single-field wrappers without PartialEq are exempt.
  isSingleTupleField(t) and
  not implementsTrait(t, "PartialEq")
}

/** Holds if file `f` is in a crate subject to codec and ordering rules. */
predicate isEnforcedCrate(File f) {
  f.getAbsolutePath().matches("%/pkgs/num/%")
  or
  f.getAbsolutePath().matches("%/pkgs/types/%") and
  not f.getAbsolutePath().matches("%/pkgs/types/marker/%")
  or
  f.getAbsolutePath().matches("%/pkgs/primitives/%")
  or
  f.getAbsolutePath().matches("%/pkgs/p2p_core/%")
  or
  f.getAbsolutePath().matches("%/pkgs/pkc/%")
  or
  f.getAbsolutePath().matches("%/pkgs/script/%")
}

/** Holds if file `f` is in a crate that can derive `Unencodable`. */
predicate isUnencodableCrate(File f) {
  f.getAbsolutePath().matches("%/pkgs/primitives/%") or
  f.getAbsolutePath().matches("%/pkgs/p2p_core/%") or
  f.getAbsolutePath().matches("%/pkgs/pkc/%") or
  f.getAbsolutePath().matches("%/pkgs/script/%")
}

/** Declaration slots that define the required source ordering. */
newtype TDeclSlot =
  TDefinition() or
  TNumCodecImpl() or
  TBaseCodecImpl() or
  TCheckableImpl() or
  THashableImpl() or
  TInherentImpl() or
  TTraitImpl()

/** A declaration slot with ordering and labelling. */
class DeclSlot extends TDeclSlot {
  /** Gets the numeric ordering key for this slot. */
  int getOrder() {
    this = TDefinition() and result = 0
    or
    this = TNumCodecImpl() and result = 1
    or
    this = TBaseCodecImpl() and result = 2
    or
    this = TCheckableImpl() and result = 3
    or
    this = THashableImpl() and result = 4
    or
    this = TInherentImpl() and result = 5
    or
    this = TTraitImpl() and result = 6
  }

  /** Gets the human-readable label. */
  string toString() {
    this = TDefinition() and result = "definition"
    or
    this = TNumCodecImpl() and result = "NumCodec impl"
    or
    this = TBaseCodecImpl() and
    result = "BaseCodec/Encode/Decode impl"
    or
    this = TCheckableImpl() and result = "Checkable impl"
    or
    this = THashableImpl() and result = "Hashable impl"
    or
    this = TInherentImpl() and result = "inherent impl"
    or
    this = TTraitImpl() and result = "trait impl"
  }
}

/** Maps a trait name to its declaration slot. */
DeclSlot traitSlot(string traitName) {
  traitName = "NumCodec" and result = TNumCodecImpl()
  or
  traitName = "BaseCodec" and result = TBaseCodecImpl()
  or
  traitName = "Encode" and result = TBaseCodecImpl()
  or
  traitName = "Decode" and result = TBaseCodecImpl()
  or
  traitName = "Checkable" and result = TCheckableImpl()
  or
  traitName = "Hashable" and result = THashableImpl()
}

/** Gets the slot for trait `trait`. */
bindingset[trait]
pragma[inline]
DeclSlot traitImplSlot(string trait) {
  result = traitSlot(trait)
  or
  not exists(traitSlot(trait)) and result = TTraitImpl()
}

/**
 * Maps `(type, slot, line, loc)` for all definition-related items.
 *
 * Keyed by `TypeItem` to avoid conflating same-named types
 * in different modules within the same file.
 */
pragma[noinline]
predicate itemEntry(TypeItem t, DeclSlot slot, int line, Locatable loc) {
  isSourceType(t) and
  (t instanceof Struct or t instanceof Enum) and
  (
    // Definition.
    slot = TDefinition() and line = startLine(t) and loc = t
    or
    // Hand-written trait impls.
    exists(Impl i, string trait |
      manualTraitImpl(t, trait, i, line) and
      slot = traitImplSlot(trait) and
      loc = i
    )
    or
    // Macro-generated trait impls (e.g. impl_type!).
    exists(Impl i, string trait |
      macroTraitImpl(t, trait, i, line) and
      slot = traitImplSlot(trait) and
      loc = i
    )
    or
    // Inherent impl.
    exists(Impl i |
      inherentImpl(t, i, line) and
      slot = TInherentImpl() and
      loc = i
    )
  )
}
