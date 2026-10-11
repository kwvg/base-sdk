# Changelog

All notable changes to [`dash-pkc`](https://crates.io/crates/dash-pkc) will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this crate adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `Bls{Public,Secret}Key::negate`, `BlsSecretKey::mul_tweak`, `EcdsaPublicKey::negate` and `EcdsaSecretKey::mul_tweak`.
- `BlsPkBytes::is_canonical`, `BlsSigBytes::is_canonical` and `BlsSkBytes::is_canonical`, behind the `bls` feature.
  They reject bytes that decode in the scheme only after masking, or not at all. Null bytes count as canonical.
- `EcdsaPkHash::verify_hash_canonical`, behind the `ecdsa` feature. It verifies a compact signature against a key id
  and rejects a header byte outside 27 to 34 and a high S.

### Changed

- `BlsScheme::sk_to_bytes` returns `Zeroizing<[u8; 32]>` instead of a bare array. Code that binds the result as
  `[u8; 32]` must dereference it.
- `EcdsaSecretKey::negate` takes `&self` and returns the negated key as `Result<Self, EcdsaError>` instead of negating
  in place and returning `()`, matching the other tweaks. A call that drops the return value still compiles, warned of
  only by `unused_must_use`, but leaves the key as it was. Callers must bind the result, e.g. `sk = sk.negate()?`.
- The following types serialize as raw bytes for machine-readable formats, following changes to `dash-types` and
  `dash-num`. JSON and other human-readable formats are unaffected by this change.

  `BlsPkBytes`, `BlsSigBytes`, `BlsPkHash`, `BlsShareId`, `BlsIes{Blob,Multi}Bytes`, `BlsPublicKey`, `BlsSignature`,
  `Bls{Pk,Sig}Share`, `BlsIes{Blob,Multi}`, `EcdsaPkBytes`, `EcdsaSigBytes`, `EcdsaRecSigBytes`, `EcdsaPkHash`,
  `EcdsaPublicKey`, `EcdsaSignature`, `EcdsaRecSignature`, `EddsaPkBytes`, `EddsaSigBytes`, `EddsaPkHash`,
  `EddsaPublicKey`, `EddsaSignature`.
- `BlsIesBlobBytes` and `BlsIesMultiBytes` report a length or count past the remaining input as `DecodeError::Eof`
  instead of `DecodeError::CompactSizeExceedsLimit`.

## [0.1.0-beta] - 2026-09-15

- Initial release.

[unreleased]: https://github.com/dashpay/base-sdk/compare/dash-pkc-0.1.0-beta...HEAD
[0.1.0-beta]: https://github.com/dashpay/base-sdk/releases/tag/dash-pkc-0.1.0-beta
