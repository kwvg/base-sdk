# dash-pkc C++ bindings design

Goal: a C++20, exception-free wrapper (`namespace dash_pkc`) over the
`dash-pkc` BLS module that mirrors the dashbls API surface Dash Core
consumes through `src/bls/bls.{h,cpp}`, using diplomat for a minimal-cost
FFI layer and `tl::expected` to preserve `Result<T, E>` semantics.

## Layering

```
Dash Core-shaped C++20 API      include/dash_pkc/*.hpp   namespace dash_pkc
  (tl::expected, spans, no exceptions)
diplomat-generated C++ headers  gen/                     namespace dash_pkc::ffi
  (opaque handles, diplomat::result, zero-copy slices)
dash-pkc-binds (Rust cdylib/staticlib, #[diplomat::bridge])
dash-pkc (bls feature only)
```

## Scheme dispatch

dash-pkc selects legacy (Chia) vs modern (IETF) at compile time via
`BlsScChia`/`BlsScIetf` type parameters; Dash Core selects at runtime
(`bls::bls_legacy_scheme` + per-call `fLegacy`). The bridge therefore
wraps each concept in a runtime enum over both monomorphizations:

```rust
enum Pk { Legacy(BlsPublicKey<BlsScChia>), Basic(BlsPublicKey<BlsScIetf>) }
```

Parse/serialize/sign/verify FFI entry points take an explicit
`BlsScheme { Legacy, Basic }` parameter. When an operation's scheme
differs from an operand's stored variant, the operand is converted via
the pkc `convert()` APIs (IETF-compressed-bytes interchange with full
revalidation). Mismatch is rare in practice (fork transitions,
CheckMalleable retries), so the hot path never converts.

## Surface (matches Dash Core's actual dashbls usage)

- `PrivateKey`: FromBytes (strict, 32 B), KeyGen(seed >= 32 B),
  Serialize/SerializeToArray, GetG1Element, Sign(msg, scheme),
  Aggregate, operator==, IsZero-equivalent by construction (parse
  rejects zero), Threshold `PrivateKeyShare` (added to pkc as
  `BlsSecretKey::derive_share`), DHKeyExchange.
- `G1Element` (48 B): FromBytes(scheme), Serialize(scheme) both vector
  and array forms, operator==, Aggregate, Threshold `PublicKeyShare`
  (= `derive_share`), BLS-IES encrypt.
- `G2Element` (96 B): FromBytes(scheme), Serialize(scheme) forms,
  operator==, Aggregate, AggregateSecure, Verify, VerifySecure,
  AggregateVerify (distinct messages), SubInsecure, Threshold
  `SignatureRecover` (id-tagged shares).
- Scheme façades `BasicSchemeMPL` / `LegacySchemeMPL` mirroring the
  CoreMPL subset Dash Core calls; both delegate to the same FFI with a
  scheme flag.
- BLS-IES blobs (single + multi recipient) in Dash Core's on-wire
  format, with entropy supplied by the caller (64 bytes: 32 ikm +
  32 IV seed) so the library stays RNG-free across the FFI.

Deliberately omitted (unused by Dash Core): HD/extended keys, GTElement,
Aug/Pop scheme classes, Threshold::{Sign, Verify, SignatureShare,
PrivateKeyRecover, PublicKeyRecover}, fingerprints, native relic interop.

## Semantic deltas vs dashbls (intentional)

- No exceptions: every fallible dashbls path (throwing FromBytes,
  CheckValid, LegacySchemeMPL unsupported overloads) becomes
  `tl::expected<T, dash_pkc::Error>`.
- Parse-time validation is stricter: infinity/non-subgroup encodings are
  rejected at FromBytes (Dash Core separately resets infinity via
  `impl == ImplType()`; net behavior matches, the error just surfaces
  earlier). There is no `FromBytesUnchecked`.
- Secret keys zeroize on drop; serialized secret material is wiped by
  the wrapper after use. No custom secure-allocator hook is needed or
  offered.
- Collections cross the FFI as builder handles (`push` per element +
  one call per operation) rather than reparsed byte matrices, so
  subgroup checks are never repeated.

## FFI cost model

Handles are opaque pointers to the already-validated blst affine
points; parse and subgroup checks happen exactly once. Serialization
writes into caller-provided fixed buffers (`&mut [u8]`), no
allocation. Messages/ids cross as borrowed slices.
