# Changelog

All notable changes to `dash-params` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this crate adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

- Initial release.

### Added

- `Bip9Deployments::evo_shares`, the deployment of EvoNode shared collateral and multiple owner payouts, on version
  bit 14 with the start times, windows and thresholds of `v24`. Callers that build `Bip9Deployments` must set it.

### Changed

- Each network's `AddrParams` carries its Platform bech32m HRP, `dash` on mainnet and `tdash` on testnet and regtest.

### Removed

- `LlmqType`, in favour of `dash_primitives::LlmqType`, which the consensus parameters now use. Callers import it from
  `dash-primitives` and spell `LlmqTestInstantSend` as `LlmqTestInstantsend`.
- `ChainParams::require_standard`. Every chain rejects non-standard transactions by default, so callers that read the
  flag treat it as `true`.

### Fixed

- The `v24` deployment signals on version bit 13 instead of 12, and starts on testnet at `1790208000`.
