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
from typing import cast

from common import RETCODE_ERR, RETCODE_PASS, RETCODE_SKIP


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


GREEN = "\033[32m"
RED = "\033[31m"
BOLD = "\033[1m"
DIM = "\033[2m"
RESET = "\033[0m"


def _print_stream(prefix: str, line: str, *, is_stderr: bool) -> None:
  color = RED if is_stderr else GREEN
  print(f"{color}({prefix}){RESET} {line}")


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


def _discover_linters(lint_dir: Path) -> list[Path]:
  return sorted(lint_dir.glob("lint_*.py"))


def _format_table(results: list[LintResult]) -> str:
  status_icons = {
    "pass": f"{GREEN}pass{RESET}",
    "fail": f"{RED}fail{RESET}",
    "skip": f"{DIM}skip{RESET}",
  }

  headers = ("name", "time", "stdout", "stderr", "status")
  rows: list[tuple[str, str, str, str, str]] = []
  for r in results:
    rows.append(
      (
        r.name,
        f"{r.elapsed:.2f}s",
        str(len(r.stdout_lines)),
        str(len(r.stderr_lines)),
        r.status,
      )
    )

  widths = [len(h) for h in headers]
  for row in rows:
    for i, cell in enumerate(row):
      widths[i] = max(widths[i], len(cell))

  def fmt_row(cells: tuple[str, ...], *, color: bool = False) -> str:
    parts: list[str] = []
    for i, cell in enumerate(cells):
      if color and i == len(cells) - 1:
        display = status_icons.get(cell, cell)
        parts.append(f" {display}{' ' * (widths[i] - len(cell))} ")
      else:
        parts.append(f" {cell:<{widths[i]}} ")
    return f"|{'|'.join(parts)}|"

  lines: list[str] = []
  lines.append(fmt_row(headers))
  lines.append("|" + "|".join("-" * (w + 2) for w in widths) + "|")
  for row in rows:
    lines.append(fmt_row(row, color=True))

  return "\n".join(lines)


async def _main() -> int:
  lint_dir = Path(__file__).resolve().parent
  scripts = _discover_linters(lint_dir)

  if not scripts:
    print("no lint_*.py scripts found", file=sys.stderr)
    return RETCODE_ERR

  print(f"{BOLD}running {len(scripts)} linter(s)...{RESET}\n")

  results = await asyncio.gather(*[_run_linter(s) for s in scripts])
  results = list(results)

  print(f"\n{_format_table(results)}\n")

  return (
    RETCODE_ERR if any(r.status == "fail" for r in results) else RETCODE_PASS
  )


if __name__ == "__main__":
  sys.exit(asyncio.run(_main()))
