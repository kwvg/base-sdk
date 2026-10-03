# Bazel

> [!NOTE]
> This guide assumes access to a [development shell](./devshells.md). Bazel and `buildifier` come from it, and
> `just zglock` only ever runs through it.

Bazel builds a subset of the crates so that other languages can bind them, and so that C dependencies compile with the
same pinned toolchain on every host. It supports only the nightly pinned in `rust-toolchain.toml`.

## Building

Bazel keeps all of its state in `.cache/bazel`, never in the home directory of the host.

```bash
bazel --output_user_root="${PWD}/.cache/bazel" build //pkgs/pow:dash-pow
```

`just zglock` regenerates `MODULE.bazel.lock` through the devshell, and should follow any change to `MODULE.bazel`
or to a manifest it lists.

### Profiles

`--build_profile=debug` (the default) and `--build_profile=release` select flags matching `[profile.dev]` and
`[profile.release]` in the workspace `Cargo.toml`. The workspace lints are restated in `defs.bzl`, since `rules_rust`
does not read `[lints]`.

## Linting

```bash
python3 maint/lint/lint_bazel.py
```

formats and lints the Starlark with `buildifier`. The `apply` verb rewrites what the branch changed, and `apply-all`
rewrites every file.
