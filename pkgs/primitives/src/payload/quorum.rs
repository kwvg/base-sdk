//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! LLMQ final commitment payload (type 6).

use crate::prelude::*;
use crate::support::{DynBitset, LlmqType};
use crate::{QuorumHash, QuorumVvecHash};

use dash_types::codec::{Codec, DecodeError, NumCodec};
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
    let version = u16::decode(data)?;
    let llmq_type = LlmqType::from_base(u8::decode(data)?);
    let quorum_hash = QuorumHash::decode(data)?;
    let quorum_index = if version == 2 || version == 4 {
      Some(i16::decode(data)?)
    } else {
      None
    };

    Ok(Self {
      version,
      llmq_type,
      quorum_hash,
      quorum_index,
      signers: DynBitset::decode(data)?,
      valid_members: DynBitset::decode(data)?,
      quorum_public_key: BlsPublicKeyBytes::decode(data)?,
      quorum_vvec_hash: QuorumVvecHash::decode(data)?,
      quorum_sig: BlsSignatureBytes::decode(data)?,
      members_sig: BlsSignatureBytes::decode(data)?,
    })
  }

  fn encode(&self, buf: &mut Vec<u8>) {
    self.version.encode(buf);
    self.llmq_type.to_base().encode(buf);
    self.quorum_hash.encode(buf);
    if let Some(idx) = self.quorum_index {
      idx.encode(buf);
    }
    self.signers.encode(buf);
    self.valid_members.encode(buf);
    self.quorum_public_key.encode(buf);
    self.quorum_vvec_hash.encode(buf);
    self.quorum_sig.encode(buf);
    self.members_sig.encode(buf);
  }
}

crate::codec::impl_payload!(Commitment);

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

impl Codec for FinalCommitment {
  fn decode(data: &mut &[u8]) -> Result<Self, DecodeError> {
    Ok(Self {
      version: u16::decode(data)?,
      height: bitcoin_units::BlockHeight::from_u32(u32::decode(data)?),
      commitment: Commitment::decode(data)?,
    })
  }

  fn encode(&self, buf: &mut Vec<u8>) {
    self.version.encode(buf);
    self.height.to_u32().encode(buf);
    self.commitment.encode(buf);
  }
}

crate::codec::impl_payload!(FinalCommitment);

impl fmt::Display for FinalCommitment {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "FinalCommitment {{ v{}, height: {} }}", self.version, self.height,)
  }
}
