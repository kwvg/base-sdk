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


def main() -> int:
  ruff_bin = require_bin("ruff")

  repo_root = find_up(
    Path(__file__).resolve().parent,
    lambda d: (d / "pyproject.toml").is_file(),
    "pyproject.toml",
  )
  result = subprocess.run(  # noqa: S603
    [ruff_bin, "check", str(repo_root)],
    check=False,
  )
  return result.returncode


if __name__ == "__main__":
  try:
    sys.exit(main())
  except Exception as exc:
    print(exc, file=sys.stderr)
    sys.exit(RETCODE_ERR)
