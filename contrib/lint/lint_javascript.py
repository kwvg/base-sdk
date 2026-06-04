#!/usr/bin/env python3
# coding: latin-1

#
# Copyright (c) 2026-present, The Dash Core developers
# SPDX-License-Identifier: MIT
# See the accompanying file LICENSE or https://opensource.org/license/MIT
#

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from common import RETCODE_ERR, find_up, require_bin

ESLINT_VERSION = "9.39.3"

DEFAULT_TARGETS: tuple[str, ...] = (".github/scripts",)


def main() -> int:
  npx_bin = require_bin("npx")

  repo_root = find_up(
    Path(__file__).resolve().parent,
    lambda d: (d / "pyproject.toml").is_file(),
    "pyproject.toml",
  )
  config_path = repo_root / "contrib" / "js" / "eslint.config.mjs"

  if not config_path.is_file():
    raise FileNotFoundError(f"error: eslint config not found: {config_path}")

  targets = [str(repo_root / t) for t in DEFAULT_TARGETS]

  result = subprocess.run(  # noqa: S603
    [
      npx_bin,
      "--yes",
      f"eslint@{ESLINT_VERSION}",
      "--config",
      str(config_path),
      *targets,
    ],
    check=False,
    cwd=str(repo_root),
  )
  return result.returncode


if __name__ == "__main__":
  try:
    sys.exit(main())
  except Exception as exc:
    print(exc, file=sys.stderr)
    sys.exit(RETCODE_ERR)
