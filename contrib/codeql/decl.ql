/**
 * Copyright (c) 2026-present, The Dash Core developers
 * SPDX-License-Identifier: MIT
 * See the accompanying file LICENSE or https://opensource.org/license/MIT
 *
 * @id base-sdk/decl-rules
 * @name Rules for order of definitions
 * @description Enforces: definition > NumCodec > Encodable/Decodable > inherent impl > trait impl.
 * @kind problem
 * @precision high
 * @problem.severity warning
 * @tags style
 */

import lib.files
import lib.filters
import lib.fmt
import lib.traits
import rust

/** Slot label for diagnostic messages. */
string slotLabel(int s) {
  s = 0 and result = "definition"
  or
  s = 1 and result = "NumCodec impl"
  or
  s = 2 and result = "Encodable/Decodable impl"
  or
  s = 3 and result = "inherent impl"
  or
  s = 4 and result = "trait impl"
}

/** Trait names that map to specific slots. */
int traitSlot(string traitName) {
  traitName = "NumCodec" and result = 1
  or
  traitName = "Encodable" and result = 2
  or
  traitName = "Decodable" and result = 2
}

/** Holds if file `f` is in an evaluated crate. */
predicate isEvaluatedCrate(File f) {
  f.getAbsolutePath().matches("%/pkgs/types/%") or
  f.getAbsolutePath().matches("%/pkgs/primitives/%") or
  f.getAbsolutePath().matches("%/pkgs/p2p_core/%")
}

/** Gets the line of struct or enum `name` in file `f`. */
int defLine(File f, string name) {
  exists(Struct s |
    not isTestCode(s) and
    not isMacroGenerated(s) and
    fileOf(s) = f and
    s.getName().getText() = name and
    result = startLine(s)
  )
  or
  exists(Enum e |
    not isTestCode(e) and
    not isMacroGenerated(e) and
    fileOf(e) = f and
    e.getName().getText() = name and
    result = startLine(e)
  )
}

/** Gets the slot of a hand-written `impl Trait for name` in file `f`. */
int traitImplSlot(File f, string name, string trait) {
  exists(traitImplLine(f, name, trait)) and
  (
    result = traitSlot(trait)
    or
    not exists(traitSlot(trait)) and result = 4
  )
}

/**
 * Maps `(file, name, slot, line)` for all definition-related items.
 */
predicate itemEntry(File f, string name, int slot, int line) {
  // Slot 0: struct/enum definition.
  slot = 0 and line = defLine(f, name)
  or
  // Slots 1, 2, 4: trait impls.
  exists(string trait |
    line = traitImplLine(f, name, trait) and
    slot = traitImplSlot(f, name, trait)
  )
  or
  // Slot 3: inherent impl.
  slot = 3 and line = inherentImplLine(f, name)
}

/**
 * Holds if type `name` in file `f` has a slot ordering violation:
 * a lower slot appears on a later line than a higher slot.
 * Items on the same line (from macro expansion) are allowed.
 */
predicate outOfOrder(File f, string name, int badSlot, int badLine, int priorSlot) {
  exists(int priorLine |
    itemEntry(f, name, priorSlot, priorLine) and
    itemEntry(f, name, badSlot, badLine) and
    badSlot < priorSlot and
    badLine > priorLine
  )
}

from TypeItem t, string name, string message
where
  (t instanceof Struct or t instanceof Enum) and
  name = t.getName().getText() and
  not isTestCode(t) and
  not isMacroGenerated(t) and
  not isNotEncodable(t) and
  isEvaluatedCrate(fileOf(t)) and
  exists(int badSlot, int badLine, int priorSlot |
    outOfOrder(fileOf(t), name, badSlot, badLine, priorSlot) and
    message =
      fmt("{0} {1} appears after {2}", name,
        fmt("{0} (slot {1})", slotLabel(badSlot), badSlot.toString()),
        fmt("{0} (slot {1})", slotLabel(priorSlot), priorSlot.toString()))
  )
select t, message
