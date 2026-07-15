# dashpkc (C++ bindings)

A C++20, exception-free BLS API over the [`dash-pkc`](../../..) Rust
crate, mirroring the dashbls surface Dash Core consumes. Fallible
operations return `tl::expected` instead of throwing; parsing always
validates (subgroup checks, no infinity); secret material zeroizes on
drop.

## Layout

| Path | Purpose |
|---|---|
| `include/dashpkc/*.h` | Public API: declarations only, no code |
| `include/dashpkc/vendor/` | Vendored third-party headers (`tl::expected`) |
| `src/*.cpp`, `src/detail.h` | The opinionated API implementation |
| `src/diplomat/` | Generated FFI bindings (private, see its README) |
| `rust/` | `dash-pkc-cxx`: the Rust crate composing `dash-pkc` for Dash's needs |
| `test/` | Boost.Test sanity checks of library invariants |
| `example/` | Small demo applications |

## Building

```sh
# from the repository root
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build
ctest --test-dir build          # requires Boost headers
cmake --install build --prefix /your/prefix
```

The install prefix receives `lib/libdash_pkc.a` (Rust core and C++
wrapper merged into one archive) and `include/dashpkc/`. Consumers
need only:

```cpp
#include <dashpkc/dashpkc.h>
```

Cross builds and packaging systems (Dash Core's depends) parameterize
the cargo invocation; see the cache variables at the top of the root
`CMakeLists.txt` (`DASH_PKC_CARGO`, `DASH_PKC_RUST_TARGET`,
`DASH_PKC_VENDOR_DIR`, `DASH_PKC_MACOS_MIN`).

## API model

- `PrivateKey`, `G1Element`, `G2Element`: value types; a default
  constructed object is null ("reset"), serializes as zeros and
  fails all operations, matching Dash Core's wrapper semantics.
- `BasicSchemeMPL` / `LegacySchemeMPL`: the CoreMPL subset Dash Core
  calls; the legacy flag selects Dash's pre-v19 (Chia) serialization
  and hash-to-curve.
- `Threshold::{PrivateKeyShare, PublicKeyShare, SignatureRecover}`.
- `IESBlob` / `IESMultiBlob`: BLS-IES in Dash Core's on-wire format;
  entropy is supplied by the caller.
- `Session`: libsecp256k1-style program-lifetime context owning all
  runtime caches (hash-to-G2 points, validated parses, weighted
  quorum keys, Lagrange coefficients, verification results). Create
  one at init with strong entropy; route hot operations through it.

## Regenerating the FFI layer

See `src/diplomat/README.md`.
