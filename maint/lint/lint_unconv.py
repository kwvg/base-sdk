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
from dataclasses import dataclass, field
from pathlib import Path

from common import (
  DEFAULT_BASE,
  declare_verbs,
  find_up_file,
  git_out,
  git_run,
  root_dir,
)

# File in the repository root the accepted vocabulary is read from.
CONFIG_FILENAME = "unconv.toml"

# Matches a commit subject, 'namespace%type[(scope)][!]: description'.
_PATTERN = re.compile(
  r"^(?P<namespace>[^\s%]+)"
  r"%(?P<type>[A-Za-z0-9_-]+)"
  r"(?:\((?P<scope>[^)\s]+)\))?"
  r"(?P<breaking>!)?"
  r": (?P<description>.+)$"
)

# Config keys that name a setting rather than a namespace.
_RESERVED: frozenset[str] = frozenset({"global"})


@dataclass(frozen=True)
class NamespaceConfig:
  ignore_global: bool = False
  types: frozenset[str] = field(default_factory=frozenset)
  scopes: frozenset[str] = field(default_factory=frozenset)


@dataclass(frozen=True)
class Config:
  global_types: frozenset[str] = field(default_factory=frozenset)
  namespaces: dict[str, NamespaceConfig] = field(default_factory=dict)

  @classmethod
  def load(cls, path: Path) -> Config:
    with path.open("rb") as f:
      raw = tomllib.load(f)

    global_types = frozenset(raw.get("global", {}).get("types", []))
    namespaces: dict[str, NamespaceConfig] = {}

    for key, value in raw.items():
      if key == "global" or not isinstance(value, dict):
        continue
      namespaces[key] = NamespaceConfig(
        ignore_global=value.get("ignore_global", False),
        types=frozenset(value.get("types", [])),
        scopes=frozenset(value.get("scopes", [])),
      )

    return cls(global_types=global_types, namespaces=namespaces)


def _allowed_types(namespace: str, config: Config) -> frozenset[str]:
  ns = config.namespaces.get(namespace)
  if ns is None:
    return config.global_types
  base = frozenset() if ns.ignore_global else config.global_types
  return base | ns.types


def _lint_subject(subject: str, config: Config) -> list[str]:
  """Return error strings for one commit subject line; empty list means valid"""
  subject = subject.strip()
  if not subject or subject.startswith("#") or subject.startswith("Merge "):
    return []

  m = _PATTERN.match(subject)
  if m is None:
    return ["does not match namespace%type[(scope)][!]: description"]

  namespace: str = m.group("namespace")
  commit_type: str = m.group("type")
  scope: str | None = m.group("scope")
  errors: list[str] = []

  if not namespace.isascii():
    errors.append(f"namespace {namespace!r} contains non-ASCII characters")

  if namespace in _RESERVED:
    errors.append(f"namespace {namespace!r} is reserved")
  elif namespace not in config.namespaces:
    errors.append(f"unknown namespace {namespace!r}")

  allowed = _allowed_types(namespace, config)
  if allowed and commit_type.lower() not in allowed:
    errors.append(
      f"unknown type {commit_type!r} for namespace {namespace!r}"
      f" -- valid:{', '.join(sorted(allowed))}"
    )

  ns_config = config.namespaces.get(namespace)
  if scope is not None and ns_config is not None and ns_config.scopes:
    if scope not in ns_config.scopes:
      errors.append(
        f"unknown scope {scope!r} for namespace {namespace!r}"
        f" -- valid:{', '.join(sorted(ns_config.scopes))}"
      )

  return errors


def _current_branch() -> str | None:
  result = git_run(root_dir(), "rev-parse", "--abbrev-ref", "HEAD")
  if result.returncode != 0:
    return None
  return result.stdout.strip()


def _ref_exists(ref: str) -> bool:
  result = git_run(root_dir(), "rev-parse", "--verify", "--quiet", ref)
  return result.returncode == 0


def _default_range() -> str:
  branch = _current_branch()
  if branch is None or branch == "HEAD" or branch == DEFAULT_BASE:
    return "HEAD~1..HEAD"
  for ref in (DEFAULT_BASE, f"origin/{DEFAULT_BASE}"):
    if _ref_exists(ref):
      return f"{ref}..HEAD"
  return "HEAD~1..HEAD"


def _subjects_from_commit(ref: str) -> list[str]:
  out = git_out(root_dir(), "log", "-1", "--format=%s", ref)
  return [line for line in out.splitlines() if line.strip()]


def _subjects_from_range(git_range: str) -> list[str]:
  out = git_out(root_dir(), "log", "--format=%s", git_range)
  return [line for line in out.splitlines() if line.strip()]


def main() -> int:
  parser = declare_verbs(
    "Lint commit messages against the unconventional commits format.\n"
    "Format: [namespace]%type[(scope)]: description",
    {"run": "lint whichever messages the options below select"},
  )
  source = parser.add_mutually_exclusive_group(required=False)
  source.add_argument(
    "-m",
    metavar="MESSAGE",
    help="Lint a commit message string directly.",
  )
  source.add_argument(
    "-r",
    metavar="RANGE",
    help="Git log range to check (e.g. main..HEAD).",
  )
  source.add_argument(
    "-c",
    metavar="COMMIT",
    help="Git commit ref to check (e.g. HEAD, abc123).",
  )
  parser.add_argument(
    "-f",
    metavar="FILE",
    type=Path,
    help=f"Path to config file (default: search upward for {CONFIG_FILENAME}).",
  )
  args = parser.parse_args()

  config_path: Path | None = args.f
  if config_path is None:
    config_path = find_up_file(root_dir(), CONFIG_FILENAME)
  if config_path is None:
    print(
      f"error: {CONFIG_FILENAME} not found (searched from {root_dir()})",
      file=sys.stderr,
    )
    return 2

  config = Config.load(config_path)

  if args.m is not None:
    subjects = [args.m]
  elif args.r is not None:
    subjects = _subjects_from_range(args.r)
  elif args.c is not None:
    subjects = _subjects_from_commit(args.c)
  else:
    subjects = _subjects_from_range(_default_range())

  results = [(s, _lint_subject(s, config)) for s in subjects]
  failed = False

  for subject, errors in results:
    if errors:
      print(f"[FAIL] {subject} (reason: {'; '.join(errors)})")
      failed = True
    else:
      print(f"[PASS] {subject}")

  return 1 if failed else 0


if __name__ == "__main__":
  sys.exit(main())
