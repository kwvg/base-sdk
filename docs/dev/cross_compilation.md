# Cross Compilation

> [!WARNING]
> The following presumes you are in the `#dev` [development shell](./devshell.md). Cross-compilation lives there and
> nowhere else: `#ci` carries no cross driver, no `CC_` and no `CARGO_TARGET_` variable, and a cross build attempted
> from it will fail at the point a C dependency or a linker is reached.

A cross target needs more than a Rust `std`: a C compiler configured for it, a sysroot to compile against, and a
linker that emits the right object format. The dev shell wires all three per target, so a cross build is the same
`cargo` invocation as a native one with `--target` added.

## Targets

The host's own target is not in this table. The shell's compiler already builds for it, so nothing has to be wired.

| Target | Object format | Sysroot |
| ------ | ------------- | ------- |
| `x86_64-pc-windows-gnu` | PE32+ | MinGW-w64 headers and import libraries |
| `x86_64-unknown-linux-gnu` | ELF | glibc |
| `aarch64-unknown-linux-gnu` | ELF | glibc |
| `x86_64-apple-darwin` | Mach-O | Xcode-extracted macOS SDK |
| `aarch64-apple-darwin` | Mach-O | Xcode-extracted macOS SDK |
| `wasm32-unknown-unknown` | Wasm | *None*, no C toolchain is wired for it |

`wasm32-unknown-unknown` is the exception that both shells carry, since nothing needs a C compiler to reach it. It is
what the documentation's WebAssembly demos are built for.

> [!NOTE]
> There is no Windows host in this set because Nix does not run there. Windows artifacts are cross-built, which is why
> the target is present while the platform is not one the flake answers for.

## Building

```bash
cargo build --workspace --features full --target x86_64-pc-windows-gnu
```

> [!TIP]
> A library-only build can succeed without a linker ever running, which makes a broken cross toolchain look healthy.
> Pass `--tests` (or `--all-targets`) when you want to know that the target links.

```bash
cargo build --all-targets --features full --target aarch64-apple-darwin
```

Each target arrives with a C driver, a C++ driver, an archiver and a linker, named the way `cc-rs` and `cargo` expect
to find them, so a crate with a C dependency needs no further configuration.

| Variable | Names |
| -------- | ----- |
| `CC_<target>` | The C driver for that target |
| `CXX_<target>` | The C++ driver for that target |
| `AR_<target>` | The archiver, `llvm-ar` |
| `CARGO_TARGET_<TARGET>_LINKER` | What `cargo` links that target's binaries with |

## Platform notes

### Windows

`rustc` shells out to `<target>-dlltool` for the raw-dylib imports that `windows-sys` declares, and looks for that
exact name rather than `llvm-dlltool`, so the MinGW binutils are on `PATH` under their target-prefixed names.

### Linux

glibc splits its outputs, so there is no single tree to hand `--sysroot`; headers, the C runtime objects and `libgcc`
are named to the driver separately. Nothing about that is visible from a `cargo` invocation.

### macOS

> [!NOTE]
> `x86_64-apple-darwin` stays reachable as a target for as long as the SDK and LLVM supply it, since neither depends on
> what `nixpkgs` supports on Darwin. What it is worth shipping is a separate question: macOS 27 requires Apple silicon,
> so those artifacts serve machines held at macOS Tahoe 26 or earlier. Intel Macs as a *host* are covered under
> [Development Shell](./devshell.md#nix).

The macOS targets compile against the Xcode-extracted SDK that Bitcoin Core and Dash Core cross-build against
([source](https://bitcoincore.org/depends-sources/sdks/)), because `nixpkgs`' own Apple SDK is Darwin-only and its
cross sets want `cctools`, which is unavailable on Linux. Artifacts are built with a macOS 14.0 floor.

> [!NOTE]
> The SDK is a download of its own, on the order of a gigabyte, fetched the first time a Darwin target is reached from
> a host that is not already Darwin.

## Adding a target

The enumeration is a table in [`contrib/nix/mods/cxx.nix`](../../contrib/nix/mods/cxx.nix). An entry names the triple
`clang` wants, which of the three sysroot recipes applies, and where the pieces come from; the drivers, the variables
and the Rust toolchain's target list all follow from it, so the shell cannot offer a `std` for a target whose C
toolchain is missing, or the reverse.
