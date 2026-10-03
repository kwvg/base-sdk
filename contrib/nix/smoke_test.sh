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

# Bazel resolves its own C++ toolchain, so it is checked apart from the
# drivers above.
if command -v bazel > /dev/null && command -v just > /dev/null; then
  root=$(git rev-parse --show-toplevel)

  if (cd "${root}" && just zbld::cxx > /dev/null 2>&1); then
    say bazel cpp "host, passed"
  else
    say bazel cpp FAILED
    status=1
  fi

  # Checked by the format in the binary, as a cross build that quietly
  # produced the host's would still exit 0. The Windows binary carries its
  # suffix, as the MinGW linker adds one.
  for slice in \
    "macos_arm64|cxxtest|Mach-O 64-bit arm64 executable" \
    "macos_x86_64|cxxtest|Mach-O 64-bit x86_64 executable" \
    "windows_x86_64|cxxtest.exe|PE32+ executable*x86-64";
  do
    IFS='|' read -r platform binary want <<< "${slice}"
    probe="${root}/bazel-bin/contrib/meta/cxxtest/${binary}"
    rm -f -- "${probe}"
    # shellcheck disable=SC2053
    if (cd "${root}" && just zbld::cxx "${platform}" > /dev/null 2>&1) &&
      [[ "$(file -b "${probe}")" == *${want}* ]]; then
      say "bazel ${platform}" cpp "$(file -b "${probe}" | cut -d, -f1)"
    else
      say "bazel ${platform}" cpp FAILED
      status=1
    fi
  done

  # A Rust DLL that reaches C through dash-pkc, so it covers the Rust and C
  # linkers together.
  dll="${root}/bazel-bin/contrib/meta/rustdll/rustdll.dll"
  rm -f -- "${dll}"
  if (cd "${root}" && just zbld::dll windows_x86_64 > /dev/null 2>&1) &&
    [[ "$(file -b "${dll}")" == *"PE32+ executable"*"(DLL)"*"x86-64"* ]]; then
    say "bazel windows_x86_64" rs "$(file -b "${dll}" | cut -d, -f1)"
  else
    say "bazel windows_x86_64" rs FAILED
    status=1
  fi
else
  say bazel cpp skipped
fi

exit "${status}"
