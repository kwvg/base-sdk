#!/usr/bin/env python3
# coding: latin-1

#
# Copyright (c) 2026-present, The Dash Core developers
# SPDX-License-Identifier: MIT
# See the accompanying file LICENSE or https://opensource.org/license/MIT
#

"""Runs semgrep rules against the workspace."""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path


def _find_workspace_root(start: Path) -> Path:
  """Walk upward from *start* until a workspace Cargo.toml is found."""
  for directory in (start, *start.parents):
    cargo = directory / "Cargo.toml"
    if (
      cargo.is_file()
      and "[workspace]" in cargo.read_text()
      and (directory / "pkgs").is_dir()
    ):
      return directory
  raise FileNotFoundError("workspace Cargo.toml not found")


def main() -> int:
  semgrep_bin = shutil.which("semgrep")
  if semgrep_bin is None:
    print("error: semgrep not found in PATH", file=sys.stderr)
    return 1

  repo_root = _find_workspace_root(
    Path(__file__).resolve().parent,
  )
  config_dir = repo_root / "contrib" / "semgrep"
  target_dir = repo_root / "pkgs"

  configs: list[str] = []
  for cfg in sorted(config_dir.glob("*.yml")):
    configs.extend(["--config", str(cfg)])

  if not configs:
    print(
      "error: no semgrep configs found in contrib/semgrep/",
      file=sys.stderr,
    )
    return 1

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
  return 0 if result.returncode == 0 else 1


if __name__ == "__main__":
  sys.exit(main())
