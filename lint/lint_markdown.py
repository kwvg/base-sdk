#!/usr/bin/env python3
# coding: latin-1

#
# Copyright (c) 2026-present, The Dash Core developers
# SPDX-License-Identifier: MIT
# See the accompanying file LICENSE or https://opensource.org/license/MIT
#

"""Lint Markdown files with pymarkdownlnt."""

from __future__ import annotations

import subprocess
import sys

from common import RETCODE_ERR, require_bin, root_dir

DISABLED_RULES = "md025,md033,md041"


def main() -> int:
  pymarkdown_bin = require_bin("pymarkdownlnt")
  repo_root = root_dir()
  result = subprocess.run(  # noqa: S603
    [
      pymarkdown_bin,
      "--disable-rules",
      DISABLED_RULES,
      "scan",
      "--recurse",
      "--respect-gitignore",
      str(repo_root),
    ],
    capture_output=True,
    check=False,
    cwd=str(repo_root),
    text=True,
  )

  prefix = str(repo_root) + "/"
  for line in result.stdout.splitlines():
    print(line.replace(prefix, ""))
  for line in result.stderr.splitlines():
    print(line.replace(prefix, ""), file=sys.stderr)

  return result.returncode


if __name__ == "__main__":
  try:
    sys.exit(main())
  except Exception as exc:  # noqa: BLE001
    print(exc, file=sys.stderr)
    sys.exit(RETCODE_ERR)
