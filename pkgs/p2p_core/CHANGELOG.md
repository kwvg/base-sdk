# Changelog

All notable changes to `dash-p2p-core` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this crate adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

- Initial release.

### Added

- `ProtocolVersion::ADDRV2`, `NO_LEGACY_ISLOCK`, `DSQ_INV`, `INCREASE_MAX_HEADERS2`, `EFFICIENT_QRINFO`,
  `ISDLOCK_CYCLEHASH_UPDATE`, `PLATFORM_BAN`, `QFCOMMIT_STALE_REPROP_BAN`, `PLATFORMBAN_V2_SHORT_ID`,
  `ASSET_UNLOCK_INV` and `MIN_MASTERNODE`.
- `encode_v2_with_version`, `decode_v2_with_version`, `P2pMsg::encode_payload_with_version` and
  `P2pMsg::decode_payload_with_version`, which take the protocol version negotiated with the peer. The forms without a
  version use `ProtocolVersion::CURRENT`.
- `ShortId::min_version`, the lowest peer version a short ID is sent to.
- `MnListDiffPayload::decode_versioned`, `MnListDiffPayload::encode_versioned`,
  `SimplifiedMnListEntry::decode_versioned` and `SimplifiedMnListEntry::encode_versioned`, for the layout of a given
  protocol version.
- `sml_merkle_root`, which computes the merkle root of a full simplified masternode list along with a mutation flag.
- `MnListDiffInvalid` and `SmlEntryInvalid`, with `Checkable` implementations for `MnListDiffPayload` and
  `SimplifiedMnListEntry`.
- `NonContinuousHeaders`, with `Checkable` implementations for `Headers` and `Headers2` that reject a header whose
  `prev_hash` is not the hash of the header before it.
- `TooManyEntries`, with `Checkable` implementations that reject `Inv` and `GetData` above 50000 entries, `Addr` and
  `AddrV2Msg` above 1000 entries, and `GetHeaders` and `GetHeaders2` with locators above 101 hashes. Encoding does not
  enforce these limits, so callers split or trim larger messages before sending them.
- `BloomFilterInvalid`, with `Checkable` implementations for `BloomFilter` and `GovSync` that reject filter data above
  36000 bytes or more than 50 hash functions.

### Changed

- `P2pMsg::SendDsq`, `P2pMsg::QSendRecSigs` and `P2pMsg::Ssc` carry the new `SendDsq`, `QSendRecSigs` and
  `SyncStatusCount` payloads, and `SyncItemId` names the `ssc` item. Callers match the payload instead of a unit
  variant or raw bytes.
- `GovSync::bloom_filter` is a `BloomFilter` instead of the filter bytes alone.
- `P2pMsg::is_stub` returns `false` for `FilterClear`, `Mempool`, `GetSporks` and `QWatch`.
- `SimplifiedMnListEntry` keeps `version`, `net_info` and `operator_key` private. `net_info` replaces `service` and is
  legacy below version 3 and extended from it, and `operator_key` is a `BlsPubKey` in the scheme of the entry version.
  Callers build entries with `new`, which takes the operator key as raw bytes and returns `NetInfoVersionMismatch` for
  net info that does not match the version, and read the fields with the accessors. The JSON key `service` becomes
  `netInfo`.
- `MnListDiffPayload` holds the coinbase proof as `cb_tx_merkle_tree`, a `PartialMerkleTree`, instead of
  `total_transactions`, `merkle_hashes` and `merkle_flags`. The JSON keys move under `cbTxMerkleTree`.
- `CompressionState` keeps `version_cache` and `prev_header` private, and deserializing it rejects more than seven
  cached versions. Callers read both with the accessors.
- `InvType` gains variants for inventory types 6, 16, 21, 23 to 26, 28, 29 and 31 to 33, which decode as the named
  variants instead of `InvType::Unknown`. Callers that match `InvType` exhaustively must handle the new variants.
- `notfound` decoding rejects more than 116 entries below protocol 70242 and more than 50000 from it. The forms without
  a version use `ProtocolVersion::CURRENT`, which is below 70242, so callers that accept up to 50000 entries must pass
  a peer version of 70242 or above. Encoding does not enforce the limit, so callers sending to a peer below 70242 split
  larger messages.

### Fixed

- `senddsq` and `qsendrecsigs` decode their one-byte flag, `ssc` decodes as an item id and a count, and `govsync`
  decodes the hash function count, tweak and flags of its bloom filter.
- Messages are sent by name to peers below `ProtocolVersion::BIP324_BASELINE`, and `platformban` is sent by name to
  peers below `ProtocolVersion::PLATFORMBAN_V2_SHORT_ID`.
- `mnlistdiff` decodes and encodes the layouts of peers below protocol 70230 when given the peer version.
- Version 3 simplified masternode list entries decode with extended net info and without a platform HTTP port.
- The simplified masternode list entry hash leaves out the entry version.
- `Headers2` encodes a header older than its predecessor with the full time, and compresses a forward wrap past
  `u32::MAX`.
- `Headers2` decoding rejects a first header that omits its previous hash, time or bits instead of filling them with
  zeros.
- `govsync` decoding rejects bloom filter data above 36000 bytes before reading it.
- `headers2` decoding accepts up to 8000 headers at protocol 70235 and above, which includes
  `ProtocolVersion::CURRENT`, and keeps the limit of 2000 below it. Encoding does not enforce either limit.
