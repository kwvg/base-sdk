# Changelog

All notable changes to `dash-primitives` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this crate adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

- Initial release.

### Added

- `merkle_root` and `merkle_root_mutated`, which compute a merkle root over `Hash256` leaves.
- `PartialMerkleTree`, with `MerkleMatches`, `PartialMerkleTreeInvalid` and `MAX_PARTIAL_MERKLE_TRANSACTIONS`. Its
  `Checkable` covers the structural checks, and `extract_matches` recovers the root and the matched hashes.
- `BlsPubKey`, `BlsSig` and `BlsScheme`, which tag BLS bytes with the scheme their container's version selects.
- `ProTxPayload` and `UnknownProTxVersion`, for ProTx payloads of types 1 to 4 whose unknown version ends the payload.
- `PROTX_VERSION_LEGACY_BLS`, `PROTX_VERSION_BASIC_BLS` and `PROTX_VERSION_EXT_ADDR` at the crate root.
- `Routing` and `check_routing` on `NetInfo`, `NetInfoV1`, `NetInfoV2`, `ProRegTx` and `ProUpServTx`, which reject
  unroutable service addresses when the network requires routable ones.
- `NetInfo::encode_canonical`, `NetInfoV1::encode_canonical` and `NetInfoV2::encode_canonical`, the encoding a ProTx
  payload hash covers.
- `LlmqType::LlmqTestDip0024`, `LlmqType::LlmqDevnetDip0024` and `LlmqType::LlmqNone`.
- `LlmqParams` and `LlmqType::params`, the size, minimum size and threshold of each quorum type.
- `Commitment::check`, `Commitment::is_null` and `CommitmentFault`, which cover the parts of commitment verification
  that need no chain.
- `MAXIMUM_WITHDRAWALS`, `MAX_PROPOSAL_DATA_SIZE`, `GovObject::check_proposal_data`,
  `Proposal::check_payment_address`, and `GovVoteInvalid` with a `Checkable` implementation for `GovVote`.

### Changed

- ProTx operator keys and signatures, commitment keys and signatures, and the MNHF, CbTx and asset unlock signatures
  are `BlsPubKey` or `BlsSig` instead of pkc byte bags. Their scheme follows the payload version, or is basic for
  fields added after v19. Callers build them with `BlsPubKey::from_bytes` or `BlsSig::from_bytes` and the scheme that
  `BlsScheme::from_protx_version` or `BlsScheme::from_commitment_version` returns.
- `CoinbaseCommitment`, `ProRegTx`, `ProUpServTx` and `NetInfoV2` keep their version-coupled fields private. Callers
  build them with `new`, which takes BLS values as raw bytes and rejects fields that do not match the version, and read
  them with the accessors.
- `CoinbaseCommitment` holds `best_cl_height_diff` as a `u32`, read as a range-checked CompactSize.
- `SpecialPayload` holds the four ProTx payloads as `ProTxPayload`, and `ProRegTx`, `ProUpServTx`, `ProUpRegTx` and
  `ProUpRevTx` decoding rejects a version of `0` or above `3`. Callers match `ProTxPayload::Known` for the fields.
- The `RevocationReason` variants are `TerminationOfService`, `CompromisedKeys` and `ChangeOfKeys`, for codes `1` to
  `3`.
- `Proposal` reads and writes `payment_amount` as a JSON number of DASH, and carries the declared type in `object_type`.
  `Trigger` uses snake_case JSON keys.
- `ProRegTx`, `ProUpServTx`, `ProUpRegTx` and `ProUpRevTx` hash without their signature and with the canonical net
  info encoding.
- `BlockInvalid::BadProofOfWork` and `BlockInvalid::BadMerkleRoot` display as `high-hash` and `bad-txnmrklroot`, and
  `ProTxInvalid::NetInfoInvalid` displays the reason for the kind of net info error.
- `NetAddr` requires `is_valid`, and `is_routable` excludes invalid addresses and the ranges `IsRoutable` excludes.
  Implementors of `NetAddr` must add `is_valid`.
- `BlockInvalid`, `TxInvalid`, `ProTxInvalid`, `CommitmentInvalid`, `CbTxInvalid`, `MnHardForkInvalid`,
  `AssetLockInvalid`, `AssetUnlockInvalid`, `ProposalInvalid` and `NIError` gain variants. Callers that match them
  exhaustively must handle the new variants.
- `dash-pkc` is built with its `bls` feature, which compiles `blst` and needs a C compiler for the target.

### Fixed

- Blocks with a mutated transaction list, a size above `MAX_DIP0001_BLOCK_SIZE`, or a coinbase position held by a
  transaction with more than one input are rejected.
- Transactions above `MAX_LEGACY_BLOCK_SIZE` and coinbase commitments outside the coinbase are rejected.
- A transaction with a negative version packs it sign-extended, so decoding and re-encoding it changes its bytes and its
  hash.
- Checks reject non-canonical BLS points in every payload, and ProTx checks reject versions above `3`.
- Decoding a `NetInfoV2` of unknown version reads only its version byte. Emptiness follows the version, and a legacy
  service whose address is invalid counts as empty.
- Legacy masternode services must be IPv4, network 2 addresses in `fc00::/8` stay IPv6, and IPv6 addresses embedding
  IPv4, TORv2 or internal addresses are invalid.
- `DynBitset` rejects a bit count above `MAX_SIZE`.
- Commitments are checked for type, version, bitset sizes, member counts and null fields, and commitment payloads must
  be version `1`.
- Asset unlocks with inputs or more than 32 outputs, and asset locks without exactly one valid `OP_RETURN` output that
  matches the credit outputs, are rejected.
- ProUpServTx rejects an operator payout that is neither P2PKH nor P2SH, and Evo ProTx payloads reject a null platform
  node id and platform ports that are `9999` or reuse a port.
- Proposals are checked for type, data size, address whitespace, URL whitespace and URL brackets, and votes for signal
  and outcome ranges.
- `GovVote` decoding rejects a signature that is neither 65 nor 96 bytes, and a length above 96 before reading it.
- Decoding an extended net info domain entry rejects a name above 253 bytes.
