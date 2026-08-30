/**
 * Copyright (c) 2026-present, The Dash Core developers
 * SPDX-License-Identifier: MIT
 * See the accompanying file LICENSE or https://opensource.org/license/MIT
 *
 * @id base-sdk/decl-rules
 * @name Rules for definition orders
 * @description Enforces definition order and enum variant structure.
 * @kind problem
 * @precision high
 * @problem.severity warning
 * @tags style
 */

import lib.filters
import lib.fmt
import lib.policy
import rust

predicate outOfOrder(
  TypeItem t, DeclSlot badSlot, int badLine, DeclSlot priorSlot, Locatable badItem
) {
  exists(int priorLine |
    itemEntry(t, priorSlot, priorLine, _) and
    itemEntry(t, badSlot, badLine, badItem) and
    badSlot.getOrder() < priorSlot.getOrder() and
    badLine > priorLine and
    // A macro can emit items spanning several slots on the same
    // line.  Suppress when the earlier line also contains an item
    // at or below badSlot: the bad item is correctly positioned
    // relative to that lower-slot companion.
    not exists(DeclSlot colocatedSlot |
      itemEntry(t, colocatedSlot, priorLine, _) and
      colocatedSlot.getOrder() <= badSlot.getOrder()
    )
  )
}

from Locatable item, string message
where
  exists(TypeItem t, string name |
    isSourceType(t) and
    (t instanceof Struct or t instanceof Enum) and
    not isSerdeInternalType(t) and
    not isNotEncodable(t) and
    isEnforcedCrate(fileOf(t)) and
    name = t.getName().getText() and
    exists(DeclSlot badSlot, int badLine, DeclSlot priorSlot |
      outOfOrder(t, badSlot, badLine, priorSlot, item) and
      message =
        fmt("{0} {1} appears after {2}", name,
          fmt("{0} (slot {1})", badSlot.toString(), badSlot.getOrder().toString()),
          fmt("{0} (slot {1})", priorSlot.toString(), priorSlot.getOrder().toString()))
    )
  )
select item, message
