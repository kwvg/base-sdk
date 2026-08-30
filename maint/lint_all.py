#!/usr/bin/env python3
# coding: latin-1

#
# Copyright (c) 2026-present, The Dash Core developers
# SPDX-License-Identifier: MIT
# See the accompanying file LICENSE or https://opensource.org/license/MIT
#

from __future__ import annotations

import asyncio
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, cast

if TYPE_CHECKING:
  import argparse

from common import (
  ANSI_BOLD,
  ANSI_GREEN,
  ANSI_RED,
  ANSI_RESET,
  RETCODE_ERR,
  RETCODE_PASS,
  RETCODE_SKIP,
  declare_verbs,
  format_table,
)

# Colour each verdict is reported in.
_STATUS_COLORS = {"pass": ANSI_GREEN, "fail": ANSI_RED}


@dataclass
class LintResult:
  name: str
  retcode: int | None = None
  elapsed: float = 0.0
  stdout_lines: list[str] = field(default_factory=list)
  stderr_lines: list[str] = field(default_factory=list)

  @property
  def status(self) -> str:
    if self.retcode is None:
      return "skip"
    return "pass" if self.retcode == RETCODE_PASS else "fail"


def _print_stream(prefix: str, line: str, *, is_stderr: bool) -> None:
  color = ANSI_RED if is_stderr else ANSI_GREEN
  print(f"{color}({prefix}){ANSI_RESET} {line}")


def _discover_linters(lint_dir: Path) -> list[Path]:
  return sorted(lint_dir.glob("lint_*.py"))


async def _read_stream(
  stream: asyncio.StreamReader,
  prefix: str,
  dest: list[str],
  *,
  is_stderr: bool,
) -> None:
  while True:
    raw = await stream.readline()
    if not raw:
      break
    line = raw.decode(errors="replace").rstrip("\n")
    dest.append(line)
    _print_stream(prefix, line, is_stderr=is_stderr)


def _parse_args(argv: list[str]) -> argparse.Namespace:
  parser = declare_verbs(
    "Run maint/lint/lint_*.py concurrently.",
    {"run": "run every linter and summarise the results"},
  )
  parser.add_argument(
    "--exclude",
    action="append",
    default=[],
    metavar="NAME",
    help=("linter to skip by name"),
  )
  return parser.parse_args(argv)


def _results_table(results: list[LintResult]) -> str:
  headers = ("name", "time", "stdout", "stderr", "status")
  rows: list[tuple[str, ...]] = [
    (
      r.name,
      f"{r.elapsed:.2f}s",
      str(len(r.stdout_lines)),
      str(len(r.stderr_lines)),
      r.status,
    )
    for r in results
  ]
  return format_table(headers, rows, _STATUS_COLORS)


async def _run_linter(script: Path) -> LintResult:
  name = script.stem
  result = LintResult(name=name)
  start = time.monotonic()

  proc = await asyncio.create_subprocess_exec(
    sys.executable,
    str(script),
    stdout=asyncio.subprocess.PIPE,
    stderr=asyncio.subprocess.PIPE,
  )

  stdout = cast("asyncio.StreamReader", proc.stdout)
  stderr = cast("asyncio.StreamReader", proc.stderr)

  await asyncio.gather(
    _read_stream(stdout, name, result.stdout_lines, is_stderr=False),
    _read_stream(stderr, name, result.stderr_lines, is_stderr=True),
  )

  await proc.wait()
  result.retcode = None if proc.returncode == RETCODE_SKIP else proc.returncode
  result.elapsed = time.monotonic() - start
  return result


async def _main() -> int:
  args = _parse_args(sys.argv[1:])
  lint_dir = Path(__file__).resolve().parent / "lint"
  excluded = set(args.exclude)
  scripts = [s for s in _discover_linters(lint_dir) if s.stem not in excluded]

  if not scripts:
    print("no lint_*.py scripts found", file=sys.stderr)
    return RETCODE_ERR

  print(f"{ANSI_BOLD}running {len(scripts)} linter(s)...{ANSI_RESET}\n")

  results = await asyncio.gather(*[_run_linter(s) for s in scripts])
  results = list(results)

  print(f"\n{_results_table(results)}\n")

  return (
    RETCODE_ERR if any(r.status == "fail" for r in results) else RETCODE_PASS
  )


if __name__ == "__main__":
  sys.exit(asyncio.run(_main()))
