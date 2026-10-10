# Changelog

All notable changes to `dash-params` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this crate adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

- Initial release.

### Removed

- `LlmqType`, in favour of `dash_primitives::LlmqType`, which the consensus parameters now use. Callers import it from
  `dash-primitives` and spell `LlmqTestInstantSend` as `LlmqTestInstantsend`.
