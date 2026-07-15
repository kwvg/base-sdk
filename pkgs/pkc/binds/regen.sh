#!/bin/sh
# Regenerate the diplomat C++ headers in gen/ from src/bridge.rs.
# Requires: cargo install diplomat-tool --locked (0.15.x).
set -eu
cd "$(dirname "$0")"
cargo build -p dash-pkc-binds
rm -rf gen
diplomat-tool cpp gen
