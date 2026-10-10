//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! LLMQ signing hashes and signing quorum selection.

use crate::payload::{payload_hash, Commitment, QuorumHash};
use crate::support::LlmqType;

use dash_num::Hash256;
use dash_types::codec::BaseCodec;
use dash_types::Numeric;

impl LlmqType {
  /// Hash a quorum of the type signs for the request `request_id` over the
  /// message `msg_hash`.
  pub fn sign_hash(self, quorum_hash: QuorumHash, request_id: Hash256, msg_hash: Hash256) -> Hash256 {
    payload_hash(|buf| {
      self.to_base().encode(buf);
      quorum_hash.encode(buf);
      request_id.encode(buf);
      msg_hash.encode(buf);
    })
  }

  /// Picks the quorum that signs the request `request_id`, or `None` when no
  /// quorum qualifies. `quorums` holds the active quorums of the type, as many
  /// as [`LlmqParams::signing_active_quorum_count`], newest first.
  ///
  /// A rotated type picks by quorum index. Rotated types form quorums only
  /// once DIP-0024 is active, so the type alone decides the method.
  ///
  /// [`LlmqParams::signing_active_quorum_count`]: crate::LlmqParams::signing_active_quorum_count
  pub fn select_signing_quorum(self, quorums: &[Commitment], request_id: Hash256) -> Option<&Commitment> {
    let params = self.params()?;
    if !params.use_rotation {
      return quorums.iter().min_by_key(|quorum| {
        payload_hash(|buf| {
          self.to_base().encode(buf);
          quorum.quorum_hash.encode(buf);
          request_id.encode(buf);
        })
        .to_lendian()
      });
    }
    let bits = params.signing_active_quorum_count.checked_ilog2()?;
    let mut word = [0; 8];
    word.copy_from_slice(&request_id.as_bytes()[24..]);
    // Bit 63 stays out of the index.
    let signer = ((1 << bits) - 1) & (u64::from_le_bytes(word) >> (63 - bits));
    if signer > quorums.len() as u64 {
      return None;
    }
    quorums
      .iter()
      .find(|quorum| u64::try_from(quorum.quorum_index.unwrap_or(0)).ok() == Some(signer))
  }
}

#[cfg(test)]
mod tests {
  use crate::payload::{Commitment, QuorumHash, QuorumVvecHash};
  use crate::prelude::*;
  use crate::support::{DynBitset, LlmqType};
  use crate::types::{BlsPubKey, BlsScheme, BlsSig};

  use dash_num::Hash256;
  use dash_types::Numeric;
  use hex_conservative::hex;
  use rstest::rstest;

  #[rstest]
  fn sign_hash_covers_the_type_quorum_request_and_message() {
    // Python hashlib gives the expected hash over the type byte 4, then 32
    // bytes each of 0x11, 0x22 and 0x33.
    let expected = Hash256::from_lendian(hex!("fc87b3be27f4fbbe26c88e25ab20fb0421b40c43e2d00ae08453f1e4d9636bcb"));
    let quorum_hash = QuorumHash::from_lendian([0x11; 32]);
    let request_id = Hash256::from_lendian([0x22; 32]);
    let msg_hash = Hash256::from_lendian([0x33; 32]);
    let llmq_type = LlmqType::Llmq100_67;
    assert_eq!(llmq_type.sign_hash(quorum_hash, request_id, msg_hash), expected);
    assert_ne!(llmq_type.sign_hash(quorum_hash, msg_hash, request_id), expected);
    assert_ne!(
      LlmqType::Llmq400_60.sign_hash(quorum_hash, request_id, msg_hash),
      expected
    );
  }

  fn quorum(hash_byte: u8, quorum_index: Option<i16>) -> Commitment {
    let empty = DynBitset {
      num_bits: 0,
      data: Vec::new(),
    };
    Commitment {
      version: if quorum_index.is_some() { 4 } else { 3 },
      llmq_type: LlmqType::Llmq60_75,
      quorum_hash: QuorumHash::from_lendian([hash_byte; 32]),
      quorum_index,
      signers: empty.clone(),
      valid_members: empty,
      quorum_public_key: BlsPubKey::from_bytes([0; 48], BlsScheme::Basic),
      quorum_vvec_hash: QuorumVvecHash::from_lendian([0; 32]),
      quorum_sig: BlsSig::from_bytes([0; 96], BlsScheme::Basic),
      members_sig: BlsSig::from_bytes([0; 96], BlsScheme::Basic),
    }
  }

  /// Request id whose bits 56 to 63 are `top` and whose other bits are zero.
  fn request_id(top: u8) -> Hash256 {
    let mut bytes = [0; 32];
    bytes[31] = top;
    Hash256::from_lendian(bytes)
  }

  #[rstest]
  #[case::llmq_50_60(LlmqType::Llmq50_60, 0x03)]
  #[case::llmq_100_67(LlmqType::Llmq100_67, 0x04)]
  fn non_rotated_types_pick_the_lowest_score(#[case] llmq_type: LlmqType, #[case] expected: u8) {
    // Python hashlib scores each quorum over the type byte, 32 bytes of the
    // quorum's byte and 32 bytes of 0x22, and compares the digests bytewise.
    let quorums: Vec<_> = (0x01..=0x04).map(|byte| quorum(byte, None)).collect();
    let picked = llmq_type.select_signing_quorum(&quorums, Hash256::from_lendian([0x22; 32]));
    assert_eq!(picked, Some(&quorum(expected, None)));
  }

  #[rstest]
  fn equal_scores_pick_the_newest_quorum() {
    let quorums = [quorum(0x01, Some(1)), quorum(0x01, Some(2))];
    let picked = LlmqType::Llmq100_67.select_signing_quorum(&quorums, request_id(0));
    assert_eq!(picked, Some(&quorums[0]));
  }

  #[rstest]
  #[case::index_0(0x00, Some(0))]
  #[case::index_3(0x0c, Some(3))]
  #[case::low_bits_ignored(0x0f, Some(3))]
  #[case::bit_63_ignored(0x8c, Some(3))]
  #[case::index_31(0x7c, Some(31))]
  fn rotated_types_pick_by_quorum_index(#[case] top: u8, #[case] expected: Option<i16>) {
    let quorums: Vec<_> = (0..32).map(|index| quorum(index as u8, Some(index))).collect();
    let picked = LlmqType::Llmq60_75.select_signing_quorum(&quorums, request_id(top));
    assert_eq!(picked.map(|quorum| quorum.quorum_index), expected.map(Some));
  }

  #[rstest]
  fn rotated_index_past_the_quorum_count_picks_none() {
    let quorums = [quorum(0x00, Some(0)), quorum(0x02, Some(2)), quorum(0x03, Some(3))];
    let llmq_type = LlmqType::Llmq60_75;
    assert_eq!(
      llmq_type.select_signing_quorum(&quorums, request_id(0x0c)),
      Some(&quorums[2])
    );
    assert_eq!(llmq_type.select_signing_quorum(&quorums, request_id(0x04)), None);
    assert_eq!(llmq_type.select_signing_quorum(&quorums[..2], request_id(0x0c)), None);
  }

  #[rstest]
  fn rotated_quorum_without_an_index_counts_as_index_0() {
    let quorums = [quorum(0x05, None)];
    let picked = LlmqType::Llmq60_75.select_signing_quorum(&quorums, request_id(0));
    assert_eq!(picked, Some(&quorums[0]));
  }

  #[rstest]
  #[case::no_quorums(LlmqType::Llmq100_67, 0)]
  #[case::no_rotated_quorums(LlmqType::Llmq60_75, 0)]
  #[case::none_type(LlmqType::LlmqNone, 1)]
  #[case::unknown_type(LlmqType::Unknown(7), 1)]
  fn selection_without_candidates_or_params_picks_none(#[case] llmq_type: LlmqType, #[case] count: u8) {
    let quorums: Vec<_> = (0..count).map(|byte| quorum(byte, Some(0))).collect();
    assert_eq!(llmq_type.select_signing_quorum(&quorums, request_id(0)), None);
  }
}
