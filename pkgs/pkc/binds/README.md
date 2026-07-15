# binds

Language bindings for the [`dash-pkc`](..) crate.

- [`cxx/`](cxx/README.md): the C++20 `dashpkc` library Dash Core
  links against. A [diplomat](https://github.com/rust-diplomat/diplomat)
  FFI layer keeps crossings cheap (opaque handles, caller buffers, no
  per-call serialization); a hand-written wrapper supplies the
  Dash-shaped, exception-free API on top.

Bindings compose the crate's public Rust API; they add no consensus
logic of their own.
