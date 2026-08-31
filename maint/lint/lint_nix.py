#!/usr/bin/env python3
# coding: latin-1

#
# Copyright (c) 2026-present, The Dash Core developers
# SPDX-License-Identifier: MIT
# See the accompanying file LICENSE or https://opensource.org/license/MIT
#

"""Check the Nix files against nixfmt's RFC 166 style, or rewrite them."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from common import (
  DEFAULT_BASE,
  RETCODE_ERR,
  RETCODE_PASS,
  RETCODE_SKIP,
  declare_verbs,
  is_plain_file,
  require_bin,
  root_dir,
  touched,
)

SCRIPT = Path(__file__).stem


def _sources(repo_root: Path, only: list[str] | None) -> list[Path]:
  """Return the Nix to format: what git tracks, or just *only* when given."""
  if only is not None:
    return [repo_root / name for name in only]
  git = require_bin("git")
  listed = subprocess.run(  # noqa: S603
    [git, "ls-files", "*.nix"],
    capture_output=True,
    check=True,
    cwd=str(repo_root),
    text=True,
  )
  # Tracked files only: a consumer's scratch .nix under the tree, and
  # anything direnv leaves behind, are not ours to hold to a format.
  return [
    repo_root / name
    for name in listed.stdout.splitlines()
    if is_plain_file(repo_root, name)
  ]


def main() -> int:
  args = declare_verbs(
    __doc__ or "",
    {
      "check": "report every Nix file whose formatting differs",
      "apply": f"rewrite the Nix this branch changed vs {DEFAULT_BASE}",
      "apply-all": "rewrite every Nix file in the tree",
    },
  ).parse_args()

  # The formatter ships in the devshell and nowhere else, so outside it this
  # reports itself skipped rather than failing a machine without Nix.
  try:
    nixfmt_bin = require_bin("nixfmt")
  except FileNotFoundError as e:
    print(f"{e}, skipping", file=sys.stderr)
    return RETCODE_SKIP

  repo_root = root_dir()
  fix = args.verb.startswith("apply")
  only = touched(repo_root, (".nix",)) if args.verb == "apply" else None
  sources = _sources(repo_root, only)

  if not sources:
    print(f"{SCRIPT}: no Nix file was touched")
    return RETCODE_PASS

  result = subprocess.run(  # noqa: S603
    [nixfmt_bin, *([] if fix else ["--check"]), *[str(p) for p in sources]],
    check=False,
    cwd=str(repo_root),
  )
  if result.returncode != 0:
    if not fix:
      print(
        f"hint: run 'python3 maint/lint/{SCRIPT}.py apply-all' to rewrite",
        file=sys.stderr,
      )
    return RETCODE_ERR

  scope = (
    f"{len(sources)} touched Nix file(s)"
    if only is not None
    else f"every Nix file ({len(sources)})"
  )
  print(f"{SCRIPT}: rewrote {scope}" if fix else f"{SCRIPT}: {scope} conforms")
  return RETCODE_PASS


if __name__ == "__main__":
  try:
    sys.exit(main())
  except Exception as exc:  # noqa: BLE001
    print(exc, file=sys.stderr)
    sys.exit(RETCODE_ERR)
