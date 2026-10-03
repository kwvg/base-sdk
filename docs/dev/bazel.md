# Bazel

> [!NOTE]
> This guide assumes access to a [development shell](./devshells.md). Bazel and `buildifier` come from it, and
> `just zglock` only ever runs through it.

Bazel builds a subset of the crates so that other languages can bind them, and so that C dependencies compile with the
same pinned toolchain on every host. It supports only the nightly pinned in `rust-toolchain.toml`.

## Building

`just` has a module for each build system, with one recipe per crate.

```bash
just cbld::pow   # cargo build -p dash-pow --features full
just zbld::pow   # the same crate under Bazel
```

`zbld` covers `pow`, `types` and `num`. The other crates answer `unsupported crate`. Both modules build every crate with
its `full` feature set, so the two systems build the same code.

Bazel keeps all of its state in `.cache/bazel`, never in the home directory of the host. This is enforced by the
`zbld` recipes, which are the supported way to invoke it.

On macOS, `zbld` also mounts a 1 GiB RAM disk at `/Volumes/bsdk-sandbox` for the sandbox. Staging thousands of input
links per action is slow on the journaled HFS+ volumes external drives often carry. `just zbld::eject` detaches it.

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

formats and lints the Starlark with `buildifier`, and checks that the crates Bazel builds match what cargo
resolves. First-party `crate_features` must equal cargo's, third-party features may be narrower but never wider.

The `apply` verb rewrites what the branch changed, and `apply-all`
rewrites every file.

## How the crate graph is resolved

`rules_rust` reads `Cargo.toml` through `crate_universe`, which needs one place to start from. That is
`contrib/meta/bazel`, the `dash-meta-bazel` crate, which depends on every crate Bazel builds with `features = ["full"]`.
Its manifest and those of the crates it names are listed under `crate.from_cargo` in `MODULE.bazel`.

`crate_universe` unifies third-party features across the whole workspace with every feature on, as `cargo metadata`
does. A third-party crate built by Bazel may therefore carry more features than `cargo build -p <crate>` would give it.
First-party crates restate their features in `crate_features`.

### Adding a crate

1. Add a `BUILD.bazel` beside its manifest, copying a sibling, with `crate_features` set to its `full` features.
2. Add the crate to the dependencies of `contrib/meta/bazel/Cargo.toml` and its manifest to `MODULE.bazel`.
3. Add a `zbld` recipe, and run `just zglock`.
