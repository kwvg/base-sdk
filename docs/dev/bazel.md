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

`zbld` covers `pow`, `types`, `num` and `pkc`. The other crates answer `unsupported crate`. Both modules build every
crate with its `full` feature set, so the two systems build the same code.

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

## C and C++

Bazel pins its own C and C++ toolchain, LLVM 20 from `toolchains_llvm`, rather than the drivers described in
[Cross Compilation](./cross_compilation.md). A `*-sys` crate compiles with it too, which is how Rust exercises it.

```bash
just zbld::cxx   # build and run contrib/meta/cxxtest on the host
```

`contrib/meta/cxxtest` is a small C++20 program that includes `<string>`, so it fails if the toolchain or its sysroot
cannot be found. `contrib/nix/smoke_test.sh` runs it. The platforms in `//platforms` name other targets for
`--platforms`, which `just zbld::cxx <platform>` accepts.

### macOS

The macOS sysroot is the Xcode SDK extract, handed over through `MACOS_SDK_SYSROOT` by the devshell, so that no Xcode is
needed on any host.

```bash
just zbld::cxx macos_x86_64   # cross-build it for another macOS slice
```

`contrib/nix/smoke_test.sh` builds both macOS slices, and checks the architecture of what they produce.

### Windows

The Windows target is `x86_64-w64-mingw32`, linked by `lld` against MinGW-w64 with winpthreads, the same runtime the
cross drivers in [Cross Compilation](./cross_compilation.md) use. The devshell hands over a merged sysroot through
`MINGW_SYSROOT`. The sysroot carries `libstdc++` from the cross GCC, which is built on mcfgthread, so C++ links
`-lmcfgthread` as the drivers do.

```bash
just zbld::cxx windows_x86_64   # cross-build it for Windows
```

`toolchains_llvm` has no Windows target and `rules_cc` names MinGW binaries without `.exe`, so `patches/` carries a fix
for each. The probe is built but never run, as no Windows host is available.

Rust targets `x86_64-pc-windows-gnu` with a hashed `rust-std` from every host. `contrib/meta/rustdll` is a Rust DLL that
calls into `dash-pkc`, so building it compiles `blst` and `secp256k1` with the same toolchain and links them.

```bash
just zbld::dll windows_x86_64   # build rustdll.dll
```

`rules_rust` cannot tell `windows-gnu` from `windows-msvc` by platform constraints, so the crate graph renders its
Windows `select()` arms for the MSVC triple, and a `windows-gnu` target takes those. `rules_rust` also declares an
import library that rustc writes only for MSVC, so a third patch stops that for gnu.
