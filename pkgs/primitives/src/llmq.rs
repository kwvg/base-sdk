//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! LLMQ signing hashes.

use crate::payload::{payload_hash, QuorumHash};
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
}

#[cfg(test)]
mod tests {
  use crate::payload::QuorumHash;
  use crate::support::LlmqType;

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
}
