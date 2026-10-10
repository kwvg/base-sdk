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
- `Transaction::instance_hash`, `Transaction::is_asset_unlock_payload` and `Transaction::has_stable_txid`, with
  `ASSET_UNLOCK_QUORUM_INFO_SIZE`, `ASSET_UNLOCK_PAYLOAD_SIZE` and `ASSET_UNLOCK_STABLE_TXID_VERSION`.
- `Transaction::inputs_hash`, `Transaction::outputs_hash` and `OutputsHash`, the hashes over the spent outpoints and
  the outputs that ProTx and shared masternode signatures commit to.
- `Transaction::asset_unlock_sign_hash` and `AssetUnlock::request_id`, the message hash and the request id of an asset
  unlock's quorum signature.
- `Block::asset_unlock_merkle_root`, the root over the instance hashes of asset unlocks with a stable txid.
- `Activation` and `Deployments`, the deployment states a gated check takes. `AssetUnlock::check_deployments` and
  `AssetLock::check_deployments` reject version 2 while v24 is inactive, and `CoinbaseCommitment::check_deployments`
  requires version 4 exactly when v20 and v24 are both active.
- `MnType::collateral_amount`, the collateral a masternode of each type locks.
- `CompactSignature`, `MasternodePayoutShare` and `CollateralShare`, the 65-byte compact ECDSA signature, the owner
  payout entry of version 3 ProTx payloads and one participant's share of a shared masternode collateral.
- `ProDisTx`, `ProUpShareTx` and `ProUpSharedRegTx`, the payloads of transaction types 10 to 12, with `Checkable`
  implementations for their version, signature and key rules.
- `ProRegTx::payouts`, `ProRegTx::shares`, `ProRegTx::early_period_blocks`, `ProRegTx::early_penalty`,
  `ProRegTx::is_shared`, `ProRegTx::MIN_SHARES`, `ProRegTx::MAX_SHARES` and `ProRegTx::MAX_EARLY_PERIOD_BLOCKS`, for
  version 3 payout lists and shared registrations.
- `ProDisTx::sign_hash`, `ProRegTx::consent_hash` and `ProRegTx::sign_string`, the hash a dissolution signs, the hash
  each share owner signs to join a shared registration, and the message an external collateral key signs.
- `ProRegTx::verify_join_sigs`, which verifies each join signature of a shared registration against its share owner.
- `Transaction::check_deployments`, which rejects an output paying the shared collateral script outside a shared
  ProRegTx once v24 is active.
- `LlmqType::sign_hash` and `LlmqType::select_signing_quorum`, the hash a quorum signs for a request and the pick of
  the quorum that signs it among the active quorums the caller supplies.
- `ChainLockSig` and `InstantSendLock`, with their signing request ids, `InstantSendLockInvalid` and
  `MAX_ISLOCK_INPUTS`. Both hold their signature as basic BLS.
- `CoinbaseCommitment::best_chainlock`, the height and signature of the chainlock a coinbase commitment carries.
- `Transaction::lock_inputs`, the outpoints an InstantSend lock pins. An asset unlock pins index 0 of its withdrawal
  request id.
- `Trigger::payments`, `SuperblockPayment` and `TriggerInvalid`, which parse the payment lists of a trigger into a
  superblock schedule.

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
- An asset unlock of payload version 2 or above hashes with its last 132 bytes zeroed, so its txid and the block merkle
  root leave out the requested height, quorum hash and quorum signature. Callers that need those fields covered use
  `Transaction::instance_hash`, which the coinbase commitment of version 4 commits to.
- Asset unlock and asset lock payloads accept version 2, and the credit outputs of a version 2 asset lock may pay
  P2SH.
- `CoinbaseCommitment` accepts version 4, which adds `merkle_root_asset_unlocks`. `CoinbaseCommitment::new` takes the
  root as its last argument, so callers pass `None` below version 4. JSON carries the `merkleRootAssetUnlocks` key,
  null below version 4.
- `ProTxInvalid::BadInputsHash`, `AssetLockInvalid::CreditBadScript`, `AssetLockInvalid::Version2Inactive`,
  `AssetUnlockInvalid::Version2Inactive`, `CbTxInvalid::BadClHeightDiff` and `BlockInvalid::AssetUnlockMerkleRoot`
  are new variants. Callers that match these enums exhaustively must handle them.
- `ProRegTx` and `ProUpRegTx` decode the version 3 owner payout list, and `ProRegTx` the collateral shares with their
  join signatures and the early period terms. `ProRegTx::new` takes the payouts, shares and early terms after
  `script_payout`, and JSON carries the `payouts`, `shares`, `earlyPeriodBlocks` and `earlyPenalty` keys.
- `ProUpRegTx` keeps its version-coupled fields private. Callers build it with `ProUpRegTx::new`, which takes the
  operator key as raw bytes and the payout list, and returns an error for fields that do not match the version.
- `TxType` and `SpecialPayload` gain variants for types 10 to 12, so `Transaction::check` checks those payloads
  instead of reporting `bad-txns-type`, and checks the inputs hash of types 11 and 12. Callers that match these enums
  exhaustively must handle the new variants.
- `ProUpShareTx` and `ProUpSharedRegTx` hash without their signatures.
- `NIEntry::check` leaves the bad-port rule for services to `NetInfoV2::check`, which knows each entry's purpose.
- `ProTxInvalid` gains variants for payout lists, shared registrations and types 10 to 12, and `TxInvalid` gains
  `SharedCollateralCreate`. Callers that match these enums exhaustively must handle them.
- `dash-pkc` is built with its `ecdsa` feature, which compiles `secp256k1` and needs a C compiler for the target.
- `LlmqParams` carries the DKG and signing parameters of each quorum type, from `use_rotation` to `recovery_members`.
  Callers that build `LlmqParams` must set the new fields.
- `Trigger` JSON requires a `type` of `2` and writes it.

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
- ProTx payloads whose inputs hash does not match the transaction's inputs are rejected.
- Blocks whose coinbase commitment of version 4 commits to another asset unlock root are rejected.
- Coinbase commitments with a null chainlock and a non-zero height diff, or with a height diff at or above their
  height, are rejected.
- ProRegTx and ProUpRegTx check the owner payouts as a list before the net info, and reject a payout list with a bad
  count, reward, script or reward sum, a duplicate script, or a payout to the owner or voting key.
- Shared registrations are checked for their collateral, owner key, payouts, shares and early terms, and must pay
  their collateral to the shared collateral script. Single-owner registrations must carry no early terms.
- Platform HTTPS service entries accept port 443, which every other purpose still rejects.
