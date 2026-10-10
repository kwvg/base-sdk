# Changelog

All notable changes to `dash-script` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this crate adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

- Initial release.

### Added

- `SHARED_COLLATERAL_SCRIPT` and `is_shared_collateral_script`, the shared masternode collateral template script and
  its exact match.
- `Recipient::to_platform`, `Recipient::from_platform` and `PlatformAddrError`, for DIP-18 Platform addresses in
  bech32m. `dash-script` depends on the `no_std` `bech32` crate.

### Changed

- `AddrParams` gains `platform_hrp`. Callers that build `AddrParams` must set it to the network's bech32m HRP, `dash`
  on mainnet and `tdash` on testnet, devnet and regtest.
- `Recipient::from_base58c` returns `None` for a string that starts with the Platform HRP in any case.
