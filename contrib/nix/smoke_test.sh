#!/usr/bin/env bash

set -uo pipefail

out="${1:-$(mktemp -d)}"
mkdir -p "${out}"
printf '#include <stdio.h>\nint main(void) { puts("Hello, world!"); return 0; }\n' > "${out}/hello.c"
printf '#include <iostream>\nint main() { std::cout << "Hello, world!\\n"; }\n' > "${out}/hello.cpp"
printf 'fn main() { println!("Hello, world!"); }\n' > "${out}/hello.rs"

status=0

# `--macho` is a `llvm-objdump` flag, the GNU equivalent is unsupported.
objdump=$(command -v llvm-objdump || command -v objdump || true)

say() {
  printf '  %-26s %-4s %s\n' "$1" "$2" "$3"
}

produced() {
  local found=("${1}"*)
  [[ -e "${found[0]}" ]]
}

try() {
  local name="$1" lang="$2" bin="${out}/${1}.${2}" want="${MACOSX_DEPLOYMENT_TARGET:-}" got kind
  shift 2
  if [[ -z "$1" ]]; then
    say "${name}" "${lang}" skipped
    return
  fi
  rm -f -- "${bin}"*
  if ! "$@" "${out}/hello.${lang}" -o "${bin}" || ! produced "${bin}"; then
    say "${name}" "${lang}" FAILED
    status=1
    return
  fi
  # An unreadable load command is a failure, not a reason to skip the check.
  if [[ "${name}" == *-apple-darwin ]]; then
    got=$("${objdump:-false}" --macho --private-headers "${bin}"* 2> /dev/null |
      awk '$1 == "minos" { print $2; exit }')
    if [[ -z "${want}" || "${got}" != "${want}" ]]; then
      say "${name}" "${lang}" "FAILED, minos ${got:-unknown}, wanted ${want:-<unset>}"
      status=1
      return
    fi
  fi
  kind=$(file -b "${bin}"* 2> /dev/null | head -1)
  say "${name}" "${lang}" "${kind:-built}"
}

try host c "${CC:-cc}"
try host cpp "${CXX:-c++}"
try host rs rustc

for target in \
  aarch64-apple-darwin \
  x86_64-apple-darwin \
  aarch64-unknown-linux-gnu \
  x86_64-unknown-linux-gnu \
  x86_64-pc-windows-gnu \
  wasm32-unknown-unknown;
do
  cc="CC_${target//-/_}"
  cxx="CXX_${target//-/_}"
  driver="${!cc:-}"
  rust="${driver:+rustc}"
  [[ "${target}" != wasm32-* ]] || rust=rustc
  try "${target}" c "${driver}"
  try "${target}" cpp "${!cxx:-}"
  try "${target}" rs "${rust}" "--target=${target}" ${driver:+"-Clinker=${driver}"}
done

exit "${status}"
