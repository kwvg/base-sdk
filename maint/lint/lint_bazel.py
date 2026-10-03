#!/usr/bin/env python3
# coding: latin-1

#
# Copyright (c) 2026-present, The Dash Core developers
# SPDX-License-Identifier: MIT
# See the accompanying file LICENSE or https://opensource.org/license/MIT
#

"""Validate Bazel's build files.

Starlark is formatted and linted with buildifier.
"""

from __future__ import annotations

import sys
from pathlib import Path

from common import (
  DEFAULT_BASE,
  RETCODE_ERR,
  RETCODE_PASS,
  RETCODE_SKIP,
  declare_verbs,
  formatted,
  git_out,
  relay,
  require_bin,
  root_dir,
  touched,
)

# Base name of this script (equivalent to argv[0]).
SCRIPT = Path(__file__).stem

# Spellings of a Starlark file buildifier understands.
STARLARK_SUFFIXES: tuple[str, ...] = (".bazel", ".bzl")


def _starlark_files(repo_root: Path) -> list[Path]:
  """Return the tracked Starlark files, sorted."""
  listed = git_out(repo_root, "ls-files", "-z").split("\0")
  return sorted(
    Path(name)
    for name in listed
    if name.endswith(STARLARK_SUFFIXES)
    and (repo_root / name).is_file()
  )


def _check_format(
  repo_root: Path,
  *,
  fix: bool,
  only: list[str] | None = None,
) -> int | None:
  """Format and lint Starlark, or None when buildifier is absent."""
  try:
    buildifier = require_bin("buildifier")
  except FileNotFoundError as e:
    print(f"{e}, skipping the Starlark check", file=sys.stderr)
    return None

  sources = (
    _starlark_files(repo_root) if only is None else [Path(n) for n in only]
  )
  mode = "fix" if fix else "check"
  return formatted(
    SCRIPT,
    "Starlark file",
    sources,
    lambda paths: [
      buildifier,
      f"--mode={mode}",
      f"--lint={'fix' if fix else 'warn'}",
      *[str(p) for p in paths],
    ],
    fix=fix,
    scoped=only is not None,
    cwd=repo_root,
    output=lambda out, err: (
      relay(out, repo_root),
      relay(err, repo_root, stream=sys.stderr),
    ),
  )


def main() -> int:
  args = declare_verbs(
    "Validate Starlark.",
    {
      "check": "report every fault, changing nothing",
      "apply": f"also rewrite Starlark this branch changed vs {DEFAULT_BASE}",
      "apply-all": "also rewrite every Starlark file in the tree",
    },
  ).parse_args(sys.argv[1:])
  fix = args.verb.startswith("apply")
  repo_root = root_dir()
  only = (
    touched(repo_root, STARLARK_SUFFIXES) if args.verb == "apply" else None
  )

  verdicts: list[int | None] = [
    _check_format(repo_root, fix=fix, only=only),
  ]
  ran = [v for v in verdicts if v is not None]
  if not ran:
    return RETCODE_SKIP
  return RETCODE_ERR if any(v != RETCODE_PASS for v in ran) else RETCODE_PASS


if __name__ == "__main__":
  try:
    sys.exit(main())
  except Exception as exc:  # noqa: BLE001
    print(exc, file=sys.stderr)
    sys.exit(RETCODE_ERR)
