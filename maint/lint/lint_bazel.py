#!/usr/bin/env python3
# coding: latin-1

#
# Copyright (c) 2026-present, The Dash Core developers
# SPDX-License-Identifier: MIT
# See the accompanying file LICENSE or https://opensource.org/license/MIT
#

"""Validate Bazel's build files and hold its crate graph to cargo's.

Starlark is formatted and linted with buildifier. The graph check asks both
build systems what they resolve for 'dash-meta-bazel', the crate whose
manifest anchors the graph, and compares the answers.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

from common import (
  DEFAULT_BASE,
  RETCODE_ERR,
  RETCODE_PASS,
  RETCODE_SKIP,
  declare_verbs,
  format_table,
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

# The crate whose manifest is the root of the graph 'crate_universe' reads.
ANCHOR = "dash-meta-bazel"

# Label of every crate Bazel builds.
ANCHOR_TARGETS = (
  "//pkgs/num:dash-num",
  "//pkgs/pkc:dash-pkc",
  "//pkgs/pow:dash-pow",
  "//pkgs/types:dash-types",
)

# Rule kinds whose 'crate_features' is a transcription of cargo's.
RUST_KINDS = "rust_library|rust_proc_macro"

# A third-party crate's repository, 'crates__<name>-<version>'.
CRATE_REPO = re.compile(r"crate\+crates__(?P<name>.+?)-(?P<version>\d[^/]*)$")

# 'name vX.Y.Z (source)|feat,feat' as 'cargo tree -f "{p}|{f}"' writes it.
TREE_ENTRY = re.compile(
  r"^(?P<name>\S+) v(?P<version>\S+)(?: \([^)]*\))*\|(?P<f>.*)$",
)

Crate = tuple[str, str]


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


def _bazel_crates(bazel: str, repo_root: Path) -> dict[Crate, set[str]]:
  """Return the features Bazel hands rustc, per crate it builds.

  Asked of 'cquery' so a 'select()' arrives flattened to the arm this build
  takes. Third-party crates are keyed by repository, workspace crates by label.
  """
  roots = " + ".join(ANCHOR_TARGETS)
  result = subprocess.run(  # noqa: S603
    [
      bazel,
      f"--output_user_root={repo_root / '.cache' / 'bazel'}",
      "cquery",
      f'kind("{RUST_KINDS}", deps({roots}))',
      "--output=jsonproto",
    ],
    capture_output=True,
    check=False,
    cwd=str(repo_root),
    text=True,
  )
  if result.returncode != 0:
    relay(result.stderr, repo_root, stream=sys.stderr)
    raise RuntimeError(f"bazel cquery failed with {result.returncode}")

  found: dict[Crate, set[str]] = {}
  for entry in json.loads(result.stdout).get("results", []):
    rule = entry["target"]["rule"]
    attrs = {a["name"]: a for a in rule["attribute"]}
    repo, _, _ = rule["name"].partition("//")
    third_party = CRATE_REPO.search(repo)
    if third_party is not None:
      key = (third_party["name"], third_party["version"])
    elif repo:
      continue
    else:
      name = attrs["crate_name"]["stringValue"].replace("_", "-")
      key = (name, "")
    features = attrs.get("crate_features", {}).get("stringListValue", [])
    found.setdefault(key, set()).update(features)
  if not found:
    raise ValueError("bazel reports no rust target for the anchor crates")
  return found


def _cargo_crates(
  cargo: str,
  repo_root: Path,
  scope: list[str],
  edges: str,
) -> dict[Crate, list[set[str]]]:
  """Return the feature sets cargo resolves for *scope*, per crate.

  A crate reached as a normal and as a build dependency can resolve twice,
  since cargo keeps host and target features apart; both sets are kept.
  """
  result = subprocess.run(  # noqa: S603
    [
      cargo,
      "tree",
      *scope,
      "--edges", edges,
      "--format", "{p}|{f}",
      "--color", "never",
      "--prefix", "none",
      "--quiet",
    ],
    capture_output=True,
    check=False,
    cwd=str(repo_root),
    text=True,
  )
  if result.returncode != 0:
    relay(result.stderr, repo_root, stream=sys.stderr)
    raise RuntimeError(f"cargo tree failed with {result.returncode}")

  resolved: dict[Crate, list[set[str]]] = {}
  for raw in result.stdout.splitlines():
    line = raw.strip().removesuffix(" (*)")
    if not line:
      continue
    entry = TREE_ENTRY.match(line)
    if entry is None:
      raise ValueError(f"unparsed cargo tree line {line!r}")
    if entry["name"] == ANCHOR:
      continue
    is_workspace = entry["name"].startswith("dash-")
    key = (entry["name"], "" if is_workspace else entry["version"])
    found = {f for f in entry["f"].split(",") if f}
    seen = resolved.setdefault(key, [])
    if found not in seen:
      seen.append(found)
  return resolved


def _check_graph(repo_root: Path) -> int | None:
  """Hold Bazel's crates and their features to cargo's, or None without a
  tool.
  """
  try:
    cargo = require_bin("cargo")
    bazel = require_bin("bazel")
  except FileNotFoundError as e:
    print(f"{e}, skipping the crate graph check", file=sys.stderr)
    return None

  theirs = _bazel_crates(bazel, repo_root)

  # The anchor's reach is the crate set Bazel must cover. Features differ,
  # since 'crate_universe' unifies them across the workspace with every
  # feature on, dev dependencies included, as 'cargo metadata' does.
  reached = _cargo_crates(
    cargo, repo_root, ["--package", ANCHOR], "normal,build",
  )
  unified = _cargo_crates(
    cargo, repo_root, ["--workspace", "--all-features"], "normal,build,dev",
  )
  print(
    f"checking crate graph: {len(theirs)} crate(s) in bazel against "
    f"{len(reached)} cargo reaches from {ANCHOR}",
  )

  def show(features: set[str]) -> str:
    return ",".join(sorted(features)) or "(none)"

  rows: list[tuple[str, ...]] = []
  for key in sorted(set(theirs) | set(reached)):
    label = f"{key[0]} {key[1]}".strip()
    if key not in theirs:
      rows.append((label, "absent", show(reached[key][0]), "missing in bazel"))
      continue
    if key not in unified:
      rows.append((label, show(theirs[key]), "absent", "extra in bazel"))
      continue
    # Workspace crates restate their features, so they must equal cargo's. A
    # third-party crate may have fewer than the workspace unifies, never more.
    first_party = key[1] == ""
    ok = any(
      theirs[key] == f if first_party else theirs[key] <= f
      for f in unified[key]
    )
    if not ok:
      rows.append((
        label,
        show(theirs[key]),
        " or ".join(show(f) for f in unified[key]),
        "features differ" if first_party else "features exceed cargo's",
      ))

  if not rows:
    print(f"{len(theirs)} crate(s) match what cargo resolves")
    return RETCODE_PASS

  print(
    format_table(("crate", "bazel", "cargo", "fault"), rows),
    file=sys.stderr,
  )
  print(f"error: {len(rows)} crate(s) differ from cargo", file=sys.stderr)
  print(
    "hint: workspace crates restate their features in 'crate_features'; "
    "third-party ones follow the manifests listed in 'MODULE.bazel', so run "
    "'just zglock' after changing a manifest",
    file=sys.stderr,
  )
  return RETCODE_ERR


def main() -> int:
  args = declare_verbs(
    "Validate Starlark and the crate graph Bazel builds.",
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
    _check_graph(repo_root),
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
