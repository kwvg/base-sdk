/**
 * Copyright (c) 2026-present, The Dash Core developers
 * SPDX-License-Identifier: MIT
 * See the accompanying file LICENSE or https://opensource.org/license/MIT
 *
 * @id base-sdk/secret-rules
 * @name Secret type restrictions
 * @description Secret types must not derive Debug.
 * @kind problem
 * @precision high
 * @problem.severity warning
 * @tags security
 */

import lib.files
import lib.filters
import lib.policy
import lib.traits
import rust

from TypeItem t
where
  isSourceType(t) and
  isSecretType(t) and
  hasDerivedImpl(t, "Debug")
select t, "secret type must not derive Debug; impl manually to redact contents"
