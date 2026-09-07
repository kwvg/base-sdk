#!/usr/bin/env bash

set -uo pipefail

out="${1:-$(mktemp -d)}"
mkdir -p "${out}"
printf '#include <stdio.h>\nint main(void) { puts("Hello, world!"); return 0; }\n' > "${out}/hello.c"
printf '#include <iostream>\nint main() { std::cout << "Hello, world!\\n"; }\n' > "${out}/hello.cpp"
printf 'fn main() { println!("Hello, world!"); }\n' > "${out}/hello.rs"

status=0

say() {
  printf '  %-26s %-4s %s\n' "$1" "$2" "$3"
}

try() {
  local name="$1" lang="$2" bin="${out}/${1}.${2}" kind
  shift 2
  if [[ -z "$1" ]]; then
    say "${name}" "${lang}" skipped
    return
  fi
  "$@" "${out}/hello.${lang}" -o "${bin}"
  if ! compgen -G "${bin}*" > /dev/null; then
    say "${name}" "${lang}" FAILED
    status=1
  else
    kind=$(file -b "${bin}"* 2> /dev/null | head -1)
    say "${name}" "${lang}" "${kind:-built}"
  fi
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
