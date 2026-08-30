/**
 * Copyright (c) 2026-present, The Dash Core developers
 * SPDX-License-Identifier: MIT
 * See the accompanying file LICENSE or https://opensource.org/license/MIT
 *
 * @id base-sdk/trait-rules
 * @name Trait definition and implementation rules
 * @description Enforces that a method body lives in one layer only.
 * @kind problem
 * @precision very-high
 * @problem.severity error
 * @tags correctness maintainability
 */

import lib.fmt
import lib.policy
import lib.traits
import rust

from Function over, string message
where
  exists(Trait t, Function decl, Impl i |
    isMutexTrait(t.getName().getText()) and
    overridesDefault(t, decl, i, over) and
    message =
      fmt("{0} overrides the default {1} provides for {2}", implSelfName(i), t.getName().getText(),
        fmt("{0}()", decl.getName().getText()))
  )
select over, message
