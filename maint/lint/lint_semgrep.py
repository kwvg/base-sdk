#!/usr/bin/env python3
# coding: latin-1

#
# Copyright (c) 2026-present, The Dash Core developers
# SPDX-License-Identifier: MIT
# See the accompanying file LICENSE or https://opensource.org/license/MIT
#

"""Runs semgrep rules against the workspace."""

from __future__ import annotations

import subprocess
import sys

from common import (
  RETCODE_ERR,
  RETCODE_PASS,
  SOURCE_DIRS,
  require_bin,
  root_dir,
)


def main() -> int:
  semgrep_bin = require_bin("semgrep")

  repo_root = root_dir()
  config_dir = repo_root / "maint" / "semgrep"
  target_dirs = [repo_root / where for where in SOURCE_DIRS]

  configs: list[str] = []
  for cfg in sorted(config_dir.glob("*.yml")):
    configs.extend(["--config", str(cfg)])

  if not configs:
    raise FileNotFoundError(
      "no semgrep configs found in maint/semgrep/",
    )

  result = subprocess.run(  # noqa: S603
    [
      semgrep_bin,
      "scan",
      *configs,
      "--error",
      *[str(d) for d in target_dirs],
    ],
    check=False,
  )
  return RETCODE_PASS if result.returncode == 0 else RETCODE_ERR


if __name__ == "__main__":
  try:
    sys.exit(main())
  except Exception as exc:  # noqa: BLE001
    print(exc, file=sys.stderr)
    sys.exit(RETCODE_ERR)
