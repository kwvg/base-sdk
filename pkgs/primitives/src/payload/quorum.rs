//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! LLMQ final commitment payload (type 6).

use crate::error::DecodeError;
use crate::prelude::*;
use crate::support::{DynBitset, LlmqType};
use crate::wire;
use crate::{QuorumHash, QuorumVvecHash};

use bitcoin_consensus_encoding as encoding;
use dash_types::{BlsPublicKeyBytes, BlsSignatureBytes};

use core::fmt;

/// DKG session output for one LLMQ.
///
/// - v1: legacy
/// - v2: legacy + indexed (quorum_index)
/// - v3: basic
/// - v4: basic + indexed (quorum_index)
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Commitment {
  /// 1=legacy, 2=+indexed, 3=basic, 4=basic+idx.
  pub version: u16,
  /// LLMQ type.
  #[cfg_attr(feature = "serde", serde(with = "crate::serialize::uint::w8"))]
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

  fn decode_for_codec(data: &[u8]) -> Result<Self, crate::codec::DecodeError> {
    Self::decode(data).map_err(Into::into)
  }

  /// Decodes from a byte slice.
  pub fn decode(data: &[u8]) -> Result<Self, DecodeError> {
    Self::decode_inner(&mut &data[..])
  }

  /// Decodes from a slice positioned mid-stream.
  pub fn decode_inner(sl: &mut &[u8]) -> Result<Self, DecodeError> {
    let version = wire::read_u16_le(sl)?;
    let llmq_type = LlmqType::from_u8(wire::read_u8(sl)?);
    let quorum_hash = wire::read_hash(sl)?.into();

    let quorum_index = if version == 2 || version == 4 {
      Some(wire::read_i16_le(sl)?)
    } else {
      None
    };

    let signers = wire::read_dynbitset(sl, 1024)?;
    let valid_members = wire::read_dynbitset(sl, 1024)?;
    let quorum_public_key = wire::read_type(sl)?;
    let quorum_vvec_hash = wire::read_hash(sl)?.into();
    let quorum_sig = wire::read_type(sl)?;
    let members_sig = wire::read_type(sl)?;

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

  /// Encodes into a byte buffer.
  pub fn encode(&self, buf: &mut Vec<u8>) {
    buf.extend_from_slice(&self.version.to_le_bytes());
    buf.push(self.llmq_type.to_u8());
    buf.extend_from_slice(self.quorum_hash.as_bytes());
    if let Some(idx) = self.quorum_index {
      buf.extend_from_slice(&idx.to_le_bytes());
    }
    crate::script::encode_compact_size(self.signers.num_bits as usize, buf);
    buf.extend_from_slice(&self.signers.data);
    crate::script::encode_compact_size(self.valid_members.num_bits as usize, buf);
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
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
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
  fn decode_for_codec(data: &[u8]) -> Result<Self, crate::codec::DecodeError> {
    Self::decode(data).map_err(Into::into)
  }

  /// Decodes from the extra_payload byte slice.
  pub fn decode(data: &[u8]) -> Result<Self, DecodeError> {
    let sl = &mut &data[..];

    let version = wire::read_u16_le(sl)?;
    let height = bitcoin_units::BlockHeight::from_u32(wire::read_u32_le(sl)?);
    let commitment = Commitment::decode_inner(sl)?;

    Ok(Self {
      version,
      height,
      commitment,
    })
  }
}

impl encoding::Decodable for Commitment {
  type Decoder = crate::codec::BufferDecoder<Self, crate::codec::DecodeError>;
  fn decoder() -> Self::Decoder {
    crate::codec::BufferDecoder::new(Self::decode_for_codec, crate::MAX_EXTRA_PAYLOAD_SIZE)
  }
}

impl encoding::Encodable for Commitment {
  type Encoder<'e> = crate::codec::VecEncoder;
  fn encoder(&self) -> Self::Encoder<'_> {
    let mut buf = Vec::new();
    self.encode(&mut buf);
    crate::codec::VecEncoder::new(buf)
  }
}

impl encoding::Decodable for FinalCommitment {
  type Decoder = crate::codec::BufferDecoder<Self, crate::codec::DecodeError>;
  fn decoder() -> Self::Decoder {
    crate::codec::BufferDecoder::new(Self::decode_for_codec, crate::MAX_EXTRA_PAYLOAD_SIZE)
  }
}
