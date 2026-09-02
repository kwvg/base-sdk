# Development Shell

The toolchain this repository builds against is a Nix development shell, defined in
[`contrib/nix`](../../contrib/nix). CI enters the same shell, so what answers a linter or compiles a crate is the same
set of programs on your host as it is on a runner, rather than whatever the host or the runner image happens to carry.

> [!NOTE]
> The shell is an alternative to managing the toolchain yourself, not a requirement. Everything in the
> [startup guide](./getting_started.md) still applies if you would rather not.

There are two ways in. [Nix](#nix) runs the shell on your host, and [Docker](#docker) carries Nix along so that a host
without it still gets the same shell.

## Nix

This guide presumes Nix has been installed on your host with the `nix-command` and `flakes` features enabled. Please
refer to vendor guidance for installation ([source](https://nixos.org/download/)); CI installs it through
[`nix-installer-action`](https://github.com/DeterminateSystems/nix-installer-action), which enables both on your behalf.

> [!WARNING]
> Intel Macs are carried on a best-effort basis and should be expected to go. macOS Tahoe 26 is the last release
> Apple supports them on, so macOS 27 requires Apple silicon
> ([source](https://www.computerworld.com/article/4122798/its-time-to-upgrade-those-old-intel-macs.html)), and
> `nixpkgs` has dropped `x86_64-darwin` from its supported systems on `unstable`, which lands with 26.11
> ([source](https://github.com/NixOS/nixpkgs/pull/536674)). The flake pins `nixos-26.05` for as long as holding that
> pin is worth what the platform returns. [Docker](#docker) is unaffected either way, since an Intel Mac running it
> gets the `x86_64-linux` shell rather than a Darwin one.

Two shells are offered.

| Shell | Carries | Suited for |
| ----- | ------- | ---------- |
| `#ci` | Both Rust toolchains, Clang, the Python environment, the linters and CodeQL | What CI runs, and a native build or test |
| `#dev` | `#ci`, plus a C driver and a Rust `std` per [cross target](./cross_compilation.md) | Local work, [cross-compilation](./cross_compilation.md) |

```bash
# The shell CI runs in
nix develop ./contrib/nix#ci

# The same, plus every cross target your host can reach
nix develop ./contrib/nix#dev
```

> [!WARNING]
> The flake sits in `contrib/nix` rather than at the repository root, so it has to be named. A bare `nix develop` will
> not find it.

A command may also be run in the shell without entering it interactively, which is how the workflows use it.

```bash
nix develop ./contrib/nix#ci --command cargo test --workspace --features full
```

### What it carries

* The `nightly` that [`rust-toolchain.toml`](../../rust-toolchain.toml) names, as `cargo`, `rustc` and `rustfmt`, with
  `wasm32-unknown-unknown` alongside your host's own target.
* The minimum supported Rust version the workspace declares, reachable by path through `TOOLCHAIN_MSRV` rather than as
  a second `cargo` (see [Toolchains are not managed by `rustup`](#toolchains-are-not-managed-by-rustup)).
* Clang 20 as the C and C++ compiler on every host, so which compiler builds a crate's C dependencies does not depend
  on where the build ran.
* The Python environment [`pyproject.toml`](../../pyproject.toml) declares: the `lib` extra resolved from
  [`uv.lock`](../../uv.lock), and the `tools` extra from `nixpkgs`. `uv` comes with it, so the lockfile can be
  regenerated in the shell that consumes it.
* What the lint suite shells out to, being `git`, `nixfmt`, `ruff`, `semgrep`, `taplo`, `node` and `pnpm`, along with
  `zensical`, `wasm-pack` and `cargo-llvm-cov` for the documentation and coverage jobs.
* CodeQL, pinned to the CLI version `github/codeql-action` resolves, since which CLI answers decides what an analysis
  reports as much as the queries do.

## Docker

> [!NOTE]
> This is not a second build environment. It is the same devshell with Nix carried along, for a host that has only
> Docker, or for a macOS or Windows host that wants the Linux shell CI uses.

```bash
cd contrib/docker
docker compose build
HOST_UID=$(id -u) HOST_GID=$(id -g) docker compose run --rm nix_shell
```

That drops you directly into `#dev`; there is nothing to run once you are in. `HOST_UID` and `HOST_GID` are what
anything written to your working tree will belong to, and both default to `1000`, so exporting them from your shell
profile or a `.env` file beside the compose file saves repeating them.

Arguments run in the shell rather than replacing it, so a script can ask for what it wants without an interactive step.

```bash
docker compose run --rm nix_shell cargo build --workspace
```

The Nix store lives in a volume and the daemon holding it keeps running after the shell exits, which is what makes a
second run cheap.

```bash
# Stop the daemon, keep the store
docker compose down

# Reclaim the store and the build cache as well
docker compose down --volumes
```

The repository is bind-mounted at `/src/base-sdk`, while `CARGO_TARGET_DIR` and `CARGO_HOME` point into a volume, which
keeps build artifacts out of your tree and keeps them between runs. For how the two services divide the store from your
user, see [`contrib/docker/README.md`](../../contrib/docker/README.md).

## Quirks

### Toolchains are not managed by `rustup`

The shell puts the toolchains on `PATH` itself, so `rustup` is not present and `cargo +name` has nothing to resolve.
Only one toolchain can own the name `cargo`, which is the pinned `nightly`; the MSRV is a path instead.

```bash
"$TOOLCHAIN_MSRV/bin/cargo" build --workspace --features full
```

`stable` is deliberately absent. It is a moving target, and a `stable` frozen by a lockfile would report a version
nobody is running, so the workflows that need it install it outside the shell.

### The first entry is expensive

`#ci` realises to some gigabytes, and `#dev` adds a sysroot per cross target on top; in the container that lands at
around 11 GiB. It is cached afterwards, so the cost is paid once, and in Docker it survives `docker compose down`.

### Tool versions differ from the lockfile

`tools` comes from `nixpkgs` while [`pyproject.toml`](../../pyproject.toml) states floors and
[`uv.lock`](../../uv.lock) states what those floors resolve to on PyPI. The two disagree, and that is accepted; for a
formatter or a linter it means a verdict can differ between the shell and an environment installed with `uv pip`.

> [!TIP]
> `taplo` is the case where the shell is the only answer. PyPI publishes no wheel for it on Arm64 Linux, so
> `lint_cargo` loses its TOML formatting half there unless the binary comes from somewhere else.

### CodeQL is emulated on Arm64 Linux

CodeQL publishes no Arm64 Linux build, so on that platform the shell emulates its executables. It works, at roughly
four times the analysis time, which is why the lint job runs on `x86_64` rather than the cheaper runner.

### The Python environment is read-only

`UV_PYTHON` points at the environment Nix built and `UV_NO_SYNC` is set, so `uv` will neither sync it nor install into
it. To add a dependency, declare it in [`pyproject.toml`](../../pyproject.toml), run `uv lock` in the shell, then
re-enter so the environment is rebuilt from the new lockfile.

### The container's shell needs its daemon

`nix_shell` holds no store of its own and asks `nix_daemon` to build over a socket, so starting it on its own reports
the missing socket and exits rather than hanging. `docker compose run` starts the daemon first and waits for it.
