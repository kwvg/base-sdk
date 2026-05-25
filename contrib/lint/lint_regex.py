#!/usr/bin/env python3
# coding: latin-1

#
# Copyright (c) 2026-present, The Dash Core developers
# SPDX-License-Identifier: MIT
# See the accompanying file LICENSE or https://opensource.org/license/MIT
#

from __future__ import annotations

import re
import sys
import tomllib
from pathlib import Path


def find_repo_root(start: Path) -> Path:
  """Walk upward from *start* until a pyproject.toml file is found."""
  for directory in (start, *start.parents):
    if (directory / "pyproject.toml").is_file():
      return directory

  raise FileNotFoundError("pyproject.toml not found")


def main() -> int:
  repo_root = find_repo_root(Path(__file__).resolve().parent)
  config_path = repo_root / "contrib" / "regex.toml"

  if not config_path.is_file():
    print(
      f"error: config not found: {config_path}",
      file=sys.stderr,
    )
    return 2

  try:
    with config_path.open("rb") as f:
      config = tomllib.load(f)
  except tomllib.TOMLDecodeError as exc:
    print(f"error: invalid TOML: {exc}", file=sys.stderr)
    return 2

  rules_table = config.get("rules")
  if not isinstance(rules_table, dict):
    print("error: missing [rules] table", file=sys.stderr)
    return 2

  compiled_rules: list[
    tuple[
      str,
      list[str],
      list[str],
      list[re.Pattern[str]],
      list[re.Pattern[str]],
      str,
    ]
  ] = []

  for rule_id, rule in rules_table.items():
    if not isinstance(rule, dict):
      print(
        f"error: rule '{rule_id}' is not a table",
        file=sys.stderr,
      )
      return 2

    for required in ("include", "block", "message"):
      if required not in rule:
        print(
          f"error: rule '{rule_id}' missing '{required}'",
          file=sys.stderr,
        )
        return 2

    try:
      block_pats = [re.compile(p) for p in rule["block"]]
      allow_pats = [re.compile(p) for p in rule.get("allow", [])]
    except re.error as exc:
      print(
        f"error: rule '{rule_id}' bad regex: {exc}",
        file=sys.stderr,
      )
      return 2

    compiled_rules.append(
      (rule_id, rule["include"], rule.get("exclude", []),
       block_pats, allow_pats, rule["message"])
    )

  findings = 0

  for (rule_id, globs, excludes,
       block_pats, allow_pats, message) in compiled_rules:
    excluded: set[Path] = set()
    for exc_glob in excludes:
      for exc_path in repo_root.glob(exc_glob):
        excluded.add(exc_path)

    seen: set[Path] = set()
    for glob in globs:
      for filepath in sorted(repo_root.glob(glob)):
        if not filepath.is_file() or filepath in seen:
          continue
        if filepath in excluded:
          continue
        seen.add(filepath)

        try:
          text = filepath.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
          continue

        relpath = filepath.relative_to(repo_root)

        for lineno, line in enumerate(text.splitlines(), 1):
          blocked = any(p.search(line) for p in block_pats)
          if not blocked:
            continue
          allowed = any(p.search(line) for p in allow_pats)
          if allowed:
            continue

          print(
            f"{relpath}:{lineno}: [{rule_id}] {message}",
            file=sys.stderr,
          )
          findings += 1

  return 1 if findings > 0 else 0


if __name__ == "__main__":
  sys.exit(main())
