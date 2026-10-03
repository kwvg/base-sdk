# Bazel builds. A crate cargo builds but Bazel cannot yet answers
# "unsupported crate". Bazel keeps all state in `.cache/bazel`.

bazel := "bazel --output_user_root=" + justfile_directory() + "/.cache/bazel"

# The sandbox lives in memory, as staging links is slow on the HFS+ volumes
# external drives often carry. Linux has `/dev/shm` already.
sandbox := if os() == "macos" { "/Volumes/bsdk-sandbox" } else { "/dev/shm" }

build := bazel + " build --sandbox_base=" + sandbox

[doc('Detach the sandbox RAM disk')]
[macos]
eject:
    -hdiutil detach {{ sandbox }}

[private]
[macos]
ramdisk:
    #!/usr/bin/env bash
    set -euo pipefail
    [[ -d "{{ sandbox }}" ]] && exit 0
    dev=$(hdiutil attach -nomount ram://2097152 | xargs)
    diskutil erasevolume HFS+ bsdk-sandbox "${dev}" > /dev/null

[private]
[linux]
ramdisk:

[doc('Unsupported under Bazel')]
dev:
    @echo "error: unsupported crate 'dev'" >&2; exit 1

[doc('Unsupported under Bazel')]
num:
    @echo "error: unsupported crate 'num'" >&2; exit 1

[doc('Unsupported under Bazel')]
p2p_core:
    @echo "error: unsupported crate 'p2p_core'" >&2; exit 1

[doc('Unsupported under Bazel')]
params:
    @echo "error: unsupported crate 'params'" >&2; exit 1

[doc('Unsupported under Bazel')]
pkc:
    @echo "error: unsupported crate 'pkc'" >&2; exit 1

[doc('Build dash-pow')]
pow: ramdisk
    {{ build }} //pkgs/pow:dash-pow

[doc('Unsupported under Bazel')]
primitives:
    @echo "error: unsupported crate 'primitives'" >&2; exit 1

[doc('Unsupported under Bazel')]
script:
    @echo "error: unsupported crate 'script'" >&2; exit 1

[doc('Unsupported under Bazel')]
types:
    @echo "error: unsupported crate 'types'" >&2; exit 1
