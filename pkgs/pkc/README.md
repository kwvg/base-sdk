# dash-pkc

Public key cryptography for the Dash SDK: BLS12-381 (both the legacy
Chia-style scheme and the IETF standard scheme, selected at compile
time via `BlsScChia` / `BlsScIetf`), secp256k1 ECDSA, threshold/LLMQ
signing primitives and BLS-IES encryption. `no_std` + `alloc`;
consensus-compatible with dashbls/Dash Core and validated against
ported known-answer vectors.

Language bindings live under [`binds/`](binds/README.md), including
the C++ library Dash Core consumes.
