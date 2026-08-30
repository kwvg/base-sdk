#!/usr/bin/env python3
# coding: latin-1

#
# Copyright (c) 2026-present, The Dash Core developers
# SPDX-License-Identifier: MIT
# See the accompanying file LICENSE or https://opensource.org/license/MIT
#

"""Validate and enforce constraints across Rust's build system, cargo.

Includes a TOML formatter using taplo that affects all TOML files regardless of
provenance or origin, exclusions must be defined in '.taplo.toml'
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
import tomllib
from pathlib import Path

from common import (
  CARGO_WORKSPACES,
  DEFAULT_BASE,
  RETCODE_ERR,
  RETCODE_PASS,
  RETCODE_SKIP,
  declare_verbs,
  format_table,
  relay,
  require_bin,
  root_dir,
  touched,
)

# Base name of this script (equivalent to argv[0]).
SCRIPT = Path(__file__).stem

# Platforms the dependency graph is resolved for.
TARGET_TRIPLES: tuple[str, ...] = (
  "x86_64-unknown-linux-gnu",
  "aarch64-unknown-linux-gnu",
)

# Leading `name vX.Y.Z` of a `cargo tree --prefix none` line. Anything after
# the version (source, ` (*)` dedupe marker, feature list) is ignored.
TREE_ENTRY = re.compile(r"^(\S+) v(\S+)")

# A package, named by its crate and the version resolved for it.
Coord = tuple[str, str]

# A semantic version, held as its components.
Version = tuple[int, ...]


def _check_format(
  repo_root: Path,
  *,
  fix: bool,
  only: list[str] | None = None,
) -> int | None:
  """Format or check TOML, or None when taplo is absent."""
  try:
    taplo = require_bin("taplo")
  except FileNotFoundError as e:
    print(f"{e}, skipping the format check", file=sys.stderr)
    return None

  if only is not None and not only:
    print(f"{SCRIPT}: no TOML file was touched")
    return RETCODE_PASS

  argv = [taplo, "fmt"] + ([] if fix else ["--check", "--diff"]) + (only or [])
  result = subprocess.run(  # noqa: S603
    argv,
    capture_output=True,
    check=False,
    cwd=str(repo_root),
    text=True,
  )
  relay(result.stdout, repo_root)

  # Taplo reports the file count on stderr at INFO, so only the lines that
  # name a fault should be emitted.
  relay(
    result.stderr,
    repo_root,
    stream=sys.stderr,
    drop=lambda line: line.lstrip().startswith("INFO"),
  )

  if result.returncode != 0:
    if not fix:
      print(
        f"hint: run 'python3 maint/lint/{SCRIPT}.py apply-all' to rewrite",
        file=sys.stderr,
      )
    return RETCODE_ERR
  scope = (
    f"{len(only)} touched TOML file(s)" if only is not None
    else "every TOML file"
  )
  print(f"{SCRIPT}: rewrote {scope}" if fix else f"{SCRIPT}: {scope} conforms")
  return RETCODE_PASS


def _parse_version(text: str) -> Version:
  """Return *text* as a comparable triple.

  Manifests write the same floor as `1.85` or `1.85.0`; padding to three
  components keeps those two spellings equal. A prerelease is not a floor
  cargo accepts, so it is raised on rather than trimmed to one.
  """
  parts = text.split(".")
  try:
    fields = [int(p) for p in parts]
  except ValueError as exc:
    raise ValueError(f"malformed rust version {text!r}") from exc
  if not 1 <= len(fields) <= 3:
    raise ValueError(f"malformed rust version {text!r}")
  return tuple(fields + [0] * (3 - len(fields)))


def _workspace_cap(repo_root: Path) -> tuple[str, Version]:
  """Return the workspace `rust-version` as written and as a tuple."""
  manifest = tomllib.loads(
    (repo_root / "Cargo.toml").read_text(encoding="utf-8"),
  )
  declared = manifest.get("workspace", {}).get("package", {}).get(
    "rust-version",
  )
  if not isinstance(declared, str):
    raise ValueError("workspace.package.rust-version is not set")
  return declared, _parse_version(declared)


def _cargo(cargo_bin: str, repo_root: Path, args: list[str]) -> str:
  """Run cargo with *args*, echoing stderr and raising on failure."""
  result = subprocess.run(  # noqa: S603
    [cargo_bin, *args],
    capture_output=True,
    check=False,
    cwd=str(repo_root),
    text=True,
  )
  relay(result.stderr, repo_root, stream=sys.stderr)
  if result.returncode != 0:
    raise RuntimeError(f"cargo {args[0]} failed with {result.returncode}")
  return result.stdout


def _build_graph(
  cargo_bin: str,
  repo_root: Path,
  workspace: str,
  triple: str,
) -> set[Coord]:
  """Return the crates cargo compiles, as `(name, version)` pairs."""
  stdout = _cargo(cargo_bin, repo_root, [
    "tree",
    "--manifest-path", str(Path(workspace) / "Cargo.toml"),
    "--workspace",
    "--all-features",
    "--locked",
    "--target", triple,
    "--edges", "normal,build,dev",
    "--prefix", "none",
    "--quiet",
  ])
  graph: set[Coord] = set()
  for raw in stdout.splitlines():
    line = raw.strip()
    if not line:
      continue
    entry = TREE_ENTRY.match(line)
    if entry is None:
      raise ValueError(f"unparsed cargo tree line {line!r}")
    graph.add((entry.group(1), entry.group(2)))
  return graph


def _declared(
  cargo_bin: str,
  repo_root: Path,
  workspace: str,
  triple: str,
) -> dict[Coord, str]:
  """Return the `rust-version` each resolved package declares."""
  stdout = _cargo(cargo_bin, repo_root, [
    "metadata",
    "--manifest-path", str(Path(workspace) / "Cargo.toml"),
    "--format-version", "1",
    "--all-features",
    "--locked",
    "--filter-platform", triple,
    "--quiet",
  ])
  return {
    (pkg["name"], pkg["version"]): pkg["rust_version"]
    for pkg in json.loads(stdout)["packages"]
    if pkg.get("rust_version")
  }


def _check_msrv(repo_root: Path) -> int | None:
  """Fail on a crate above the cap, or None when cargo is absent."""
  try:
    cargo_bin = require_bin("cargo")
  except FileNotFoundError as e:
    print(f"{e}, skipping the msrv check", file=sys.stderr)
    return None

  cap_text, cap = _workspace_cap(repo_root)
  print(f"checking msrv: cap {cap_text} ({', '.join(TARGET_TRIPLES)})")

  graph: set[Coord] = set()
  declared: dict[Coord, str] = {}
  for workspace in CARGO_WORKSPACES:
    for triple in TARGET_TRIPLES:
      graph |= _build_graph(cargo_bin, repo_root, workspace, triple)
      declared |= _declared(cargo_bin, repo_root, workspace, triple)

  # Parsed floor first, so that sorting a crate is sorting its rust-version
  # and the name only breaks ties.
  rated = sorted(
    (_parse_version(text), name, version, text)
    for (name, version), text in declared.items()
    if (name, version) in graph
  )
  if not rated:
    raise ValueError("no crate in the build graph declares a rust-version")

  highest = max(rated)[0]
  peak = [r for r in rated if r[0] == highest]

  # `rated` is already sorted, and this sort is stable, so the worst overrun
  # leads and crates sharing a floor stay in name order.
  over = sorted(
    (r for r in rated if r[0] > cap), key=lambda r: r[0], reverse=True,
  )
  summary = ", ".join(f"{n} {v}" for _, n, v, _ in peak[:3])
  if len(peak) > 3:
    summary += f", +{len(peak) - 3} more"
  top = ".".join(str(p) for p in highest)
  silent = len(graph - declared.keys())
  print(
    f"build graph of {len(graph)} crates ({silent} declaring no floor) "
    f"peaks at {top}: {summary}",
  )

  if not over:
    return RETCODE_PASS

  print(
    format_table(
      ("package", "version", "rust-version", "status"),
      [(n, v, t, "fail") for _, n, v, t in over],
    ),
    file=sys.stderr,
  )
  print(
    f"error: {len(over)} crate(s) declare a rust-version above the "
    f"{cap_text} cap",
    file=sys.stderr,
  )
  print(
    "hint: pin the offending package with "
    "'cargo update <crate> --precise <version>'",
    file=sys.stderr,
  )
  return RETCODE_ERR


def main() -> int:
  args = declare_verbs(
    "Validate the crate graph is compatible with the MSRV.",
    {
      "check": "report every fault, changing nothing",
      "apply": f"also rewrite TOML this branch changed vs {DEFAULT_BASE}",
      "apply-all": "also rewrite every TOML file in the tree",
    },
  ).parse_args(sys.argv[1:])
  fix = args.verb.startswith("apply")
  repo_root = root_dir()
  only = touched(repo_root, (".toml",)) if args.verb == "apply" else None

  verdicts: list[int | None] = [
    _check_format(repo_root, fix=fix, only=only),
    _check_msrv(repo_root),
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
