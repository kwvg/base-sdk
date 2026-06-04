#!/usr/bin/env python3
# coding: latin-1

#
# Copyright (c) 2026-present, The Dash Core developers
# SPDX-License-Identifier: MIT
# See the accompanying file LICENSE or https://opensource.org/license/MIT
#

"""Shared constants and helpers for lint scripts."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
  from collections.abc import Callable
  from pathlib import Path

RETCODE_ERR = 1
RETCODE_PASS = 0
RETCODE_SKIP = 77


def find_up(
  start: Path,
  predicate: Callable[[Path], bool],
  label: str = "matching directory",
) -> Path:
  """Walk upward from *start*, returning the first matching directory."""
  for directory in (start, *start.parents):
    if predicate(directory):
      return directory
  raise FileNotFoundError(f"{label} not found above {start}")


def is_workspace_root(d: Path) -> bool:
  """Return True if *d* looks like a Cargo workspace root."""
  cargo = d / "Cargo.toml"
  return (
    cargo.is_file()
    and "[workspace]" in cargo.read_text(encoding="utf-8")
    and (d / "pkgs").is_dir()
  )
