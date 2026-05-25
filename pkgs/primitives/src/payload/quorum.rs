//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! LLMQ final commitment payload (type 6).

use crate::prelude::*;
use crate::support::{DynBitset, LlmqType};
use crate::wire;
use crate::{QuorumHash, QuorumVvecHash};

use bitcoin_consensus_encoding as encoding;
use dash_types::codec::{self, Codec, DecodeError, NumCodec};
use dash_types::{BlsPublicKeyBytes, BlsSignatureBytes};

use core::fmt;

/// DKG session output for one LLMQ.
///
/// - v1: legacy
/// - v2: legacy + indexed (quorum_index)
/// - v3: basic
/// - v4: basic + indexed (quorum_index)
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct Commitment {
  /// 1=legacy, 2=+indexed, 3=basic, 4=basic+idx.
  pub version: u16,
  /// LLMQ type.
  pub llmq_type: LlmqType,
  /// Quorum block hash.
  pub quorum_hash: QuorumHash,
  /// Present for indexed versions (2, 4).
  pub quorum_index: Option<i16>,
  /// Signers bitset.
  pub signers: DynBitset,
  /// Valid members bitset.
  pub valid_members: DynBitset,
  /// Quorum BLS public key (48 bytes).
  pub quorum_public_key: BlsPublicKeyBytes,
  /// Quorum verification vector hash (32 bytes).
  pub quorum_vvec_hash: QuorumVvecHash,
  /// Threshold signature over commitment.
  pub quorum_sig: BlsSignatureBytes,
  /// Aggregated per-member signature.
  pub members_sig: BlsSignatureBytes,
}

impl Commitment {
  /// Returns true if this is an indexed commitment (version 2 or 4).
  #[inline]
  pub fn is_indexed(&self) -> bool {
    self.version == 2 || self.version == 4
  }
}

impl Codec for Commitment {
  fn decode(data: &mut &[u8]) -> Result<Self, DecodeError> {
    let version = codec::read_u16_le(data)?;
    let llmq_type = LlmqType::from_base(codec::read_u8(data)?);
    let quorum_hash = wire::read_hash(data)?.into();

    let quorum_index = if version == 2 || version == 4 {
      Some(codec::read_i16_le(data)?)
    } else {
      None
    };

    let signers = wire::read_dynbitset(data, 1024)?;
    let valid_members = wire::read_dynbitset(data, 1024)?;
    let quorum_public_key = codec::read_type(data)?;
    let quorum_vvec_hash = wire::read_hash(data)?.into();
    let quorum_sig = codec::read_type(data)?;
    let members_sig = codec::read_type(data)?;

    Ok(Self {
      version,
      llmq_type,
      quorum_hash,
      quorum_index,
      signers,
      valid_members,
      quorum_public_key,
      quorum_vvec_hash,
      quorum_sig,
      members_sig,
    })
  }

  fn encode(&self, buf: &mut Vec<u8>) {
    buf.extend_from_slice(&self.version.to_le_bytes());
    buf.push(self.llmq_type.to_base());
    buf.extend_from_slice(self.quorum_hash.as_bytes());
    if let Some(idx) = self.quorum_index {
      buf.extend_from_slice(&idx.to_le_bytes());
    }
    codec::write_compact_size(self.signers.num_bits as usize, buf);
    buf.extend_from_slice(&self.signers.data);
    codec::write_compact_size(self.valid_members.num_bits as usize, buf);
    buf.extend_from_slice(&self.valid_members.data);
    buf.extend_from_slice(&self.quorum_public_key.0);
    buf.extend_from_slice(self.quorum_vvec_hash.as_bytes());
    buf.extend_from_slice(&self.quorum_sig.0);
    buf.extend_from_slice(&self.members_sig.0);
  }
}

impl fmt::Display for Commitment {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "Commitment {{ v{}, llmq: {} }}", self.version, self.llmq_type,)
  }
}

/// Tx-level wrapper for Commitment (type 6).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct FinalCommitment {
  /// Payload version.
  pub version: u16,
  /// Block height.
  pub height: bitcoin_units::BlockHeight,
  /// The commitment itself.
  pub commitment: Commitment,
}

impl fmt::Display for FinalCommitment {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "FinalCommitment {{ v{}, height: {} }}", self.version, self.height,)
  }
}

impl FinalCommitment {
  /// Decodes from the extra_payload byte slice.
  pub fn decode(data: &mut &[u8]) -> Result<Self, DecodeError> {
    let version = codec::read_u16_le(data)?;
    let height = bitcoin_units::BlockHeight::from_u32(codec::read_u32_le(data)?);
    let commitment = Codec::decode(data)?;

    Ok(Self {
      version,
      height,
      commitment,
    })
  }
}

crate::codec::impl_payload!(Commitment);

impl encoding::Decodable for FinalCommitment {
  type Decoder = dash_types::BufferDecoder<Self, DecodeError>;
  fn decoder() -> Self::Decoder {
    dash_types::BufferDecoder::new(Self::decode, crate::MAX_EXTRA_PAYLOAD_SIZE)
  }
}
