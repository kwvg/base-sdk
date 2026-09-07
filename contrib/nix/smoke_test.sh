#!/usr/bin/env bash

set -uo pipefail

out="${1:-$(mktemp -d)}"
mkdir -p "${out}"
printf '#include <stdio.h>\nint main(void) { puts("Hello, world!"); return 0; }\n' > "${out}/hello.c"
printf '#include <iostream>\nint main() { std::cout << "Hello, world!\\n"; }\n' > "${out}/hello.cpp"

status=0

build() {
  local name="$1" driver="$2" ext="$3" bin="${out}/${1}.${3}" kind
  if [[ -z "${driver}" ]]; then
    printf '  %-26s %-3s skipped\n' "${name}" "${ext}"
  elif "${driver}" "${out}/hello.${ext}" -o "${bin}" && compgen -G "${bin}*" > /dev/null; then
    kind=$(file -b "${bin}"* 2> /dev/null | head -1)
    printf '  %-26s %-3s %s\n' "${name}" "${ext}" "${kind:-built}"
  else
    printf '  %-26s %-3s FAILED\n' "${name}" "${ext}"
    status=1
  fi
}

build host "${CC:-cc}" c
build host "${CXX:-c++}" cpp

for target in \
  aarch64-unknown-linux-gnu \
  x86_64-unknown-linux-gnu \
  x86_64-pc-windows-gnu;
do
  cc="CC_${target//-/_}"
  cxx="CXX_${target//-/_}"
  build "${target}" "${!cc:-}" c
  build "${target}" "${!cxx:-}" cpp
done

exit "${status}"
