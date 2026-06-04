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
from pathlib import Path

from common import (
  RETCODE_ERR,
  RETCODE_PASS,
  find_up,
  is_workspace_root,
  require_bin,
)


def main() -> int:
  semgrep_bin = require_bin("semgrep")

  repo_root = find_up(
    Path(__file__).resolve().parent,
    is_workspace_root,
    "workspace Cargo.toml",
  )
  config_dir = repo_root / "contrib" / "semgrep"
  target_dir = repo_root / "pkgs"

  configs: list[str] = []
  for cfg in sorted(config_dir.glob("*.yml")):
    configs.extend(["--config", str(cfg)])

  if not configs:
    raise FileNotFoundError(
      "no semgrep configs found in contrib/semgrep/",
    )

  result = subprocess.run(  # noqa: S603
    [
      semgrep_bin,
      "scan",
      *configs,
      "--error",
      str(target_dir),
    ],
    check=False,
  )
  return RETCODE_PASS if result.returncode == 0 else RETCODE_ERR


if __name__ == "__main__":
  try:
    sys.exit(main())
  except Exception as exc:
    print(exc, file=sys.stderr)
    sys.exit(RETCODE_ERR)
