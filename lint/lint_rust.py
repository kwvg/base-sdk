#!/usr/bin/env python3
# coding: latin-1

#
# Copyright (c) 2026-present, The Dash Core developers
# SPDX-License-Identifier: MIT
# See the accompanying file LICENSE or https://opensource.org/license/MIT
#

"""Check Rust formatting across workspace manifests."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from common import (
  CARGO_WORKSPACES,
  RETCODE_ERR,
  RETCODE_PASS,
  require_bin,
  root_dir,
)


def main() -> int:
  _ = require_bin("rustfmt")
  cargo_bin = require_bin("cargo")
  repo_root = root_dir()

  failed = False
  for workspace in CARGO_WORKSPACES:
    manifest = Path(workspace) / "Cargo.toml"
    manifest_path = repo_root / manifest
    print(f"checking formatting: {manifest}")
    cmd = [cargo_bin, "fmt", "--check", "--all"]
    cmd += ["--manifest-path", str(manifest_path)]
    result = subprocess.run(  # noqa: S603
      cmd,
      capture_output=True,
      check=False,
      cwd=str(repo_root),
      text=True,
    )
    if result.stdout:
      sys.stdout.write(result.stdout)
    if result.stderr:
      # Filter nightly-only rustfmt warnings that appear on stable.
      filtered = "\n".join(
        ln for ln in result.stderr.splitlines()
        if not (ln.startswith("Warning:") and (
          "unstable features" in ln or "has been stabilized" in ln
        ))
      )
      if filtered.strip():
        sys.stderr.write(filtered + "\n")
    if result.returncode != 0:
      failed = True

  return RETCODE_ERR if failed else RETCODE_PASS


if __name__ == "__main__":
  try:
    sys.exit(main())
  except Exception as exc:  # noqa: BLE001
    print(exc, file=sys.stderr)
    sys.exit(RETCODE_ERR)
