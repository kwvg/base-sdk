//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! BLS secret key byte bag parameterized by scheme.

use crate::bls::BlsSchemeId;
use crate::prelude::*;

use bitcoin_consensus_encoding::{Decodable, Encodable};
use bitcoin_hashes::sha256d::Hash as Sha256d;
use dash_num::Hash256;
use dash_types::codec::{take, BaseCodec, DecodeError, EncodeBuf, Hashable, TypeId};
use dash_types::{BufferDecoder, VecEncoder, MAX_SER_SIZE};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use core::fmt::{Debug, Display, Formatter, Result as FmtResult};
use core::marker::PhantomData;

/// Raw BLS secret key length (scalar).
pub const BLS_SK_LEN: usize = 32;

/// Scheme-tagged BLS secret key bytes (32 bytes, zeroized on drop).
pub struct BlsSkBytes<S: BlsSchemeId> {
  inner: [u8; BLS_SK_LEN],
  _scheme: PhantomData<S>,
}

impl<S: BlsSchemeId> Clone for BlsSkBytes<S> {
  fn clone(&self) -> Self {
    Self {
      inner: self.inner,
      _scheme: PhantomData,
    }
  }
}

impl<S: BlsSchemeId> Zeroize for BlsSkBytes<S> {
  fn zeroize(&mut self) {
    self.inner.zeroize();
  }
}

impl<S: BlsSchemeId> Drop for BlsSkBytes<S> {
  fn drop(&mut self) {
    self.zeroize();
  }
}

impl<S: BlsSchemeId> ZeroizeOnDrop for BlsSkBytes<S> {}

impl<S: BlsSchemeId> BlsSkBytes<S> {
  /// Wraps raw bytes without validation.
  pub const fn from_bytes(bytes: [u8; BLS_SK_LEN]) -> Self {
    Self {
      inner: bytes,
      _scheme: PhantomData,
    }
  }

  /// Borrows the inner byte array.
  pub const fn as_bytes(&self) -> &[u8; BLS_SK_LEN] {
    &self.inner
  }

  /// Copies out the inner bytes in a zeroizing wrapper.
  pub fn to_bytes(&self) -> Zeroizing<[u8; BLS_SK_LEN]> {
    Zeroizing::new(self.inner)
  }

  /// Returns `true` when every byte is zero.
  pub fn is_null(&self) -> bool {
    self.inner.ct_eq(&[0u8; BLS_SK_LEN]).into()
  }
}

impl<S: BlsSchemeId> AsRef<[u8; BLS_SK_LEN]> for BlsSkBytes<S> {
  fn as_ref(&self) -> &[u8; BLS_SK_LEN] {
    &self.inner
  }
}

impl<S: BlsSchemeId> TypeId for BlsSkBytes<S> {
  const TYPE_ID: u32 = S::SK_TYPE_ID;
}

impl<S: BlsSchemeId> BaseCodec for BlsSkBytes<S> {
  fn decode(data: &mut &[u8]) -> Result<Self, DecodeError> {
    take::<BLS_SK_LEN>(data).map(Self::from_bytes)
  }

  fn encode(&self, buf: &mut impl EncodeBuf) {
    buf.extend_from_slice(&self.inner);
  }
}

impl<S: BlsSchemeId> Encodable for BlsSkBytes<S> {
  type Encoder<'e> = VecEncoder;
  fn encoder(&self) -> Self::Encoder<'_> {
    let mut buf = Vec::new();
    BaseCodec::encode(self, &mut buf);
    VecEncoder::new(buf)
  }
}

impl<S: BlsSchemeId> Decodable for BlsSkBytes<S> {
  type Decoder = BufferDecoder<Self>;
  fn decoder() -> Self::Decoder {
    BufferDecoder::new(<Self as BaseCodec>::decode, MAX_SER_SIZE)
  }
}

impl<S: BlsSchemeId> Debug for BlsSkBytes<S> {
  fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
    write!(f, "BlsSkBytes<{}>(..)", S::LABEL)
  }
}

impl<S: BlsSchemeId> Display for BlsSkBytes<S> {
  fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
    Debug::fmt(self, f)
  }
}

impl<S: BlsSchemeId> Eq for BlsSkBytes<S> {}

impl<S: BlsSchemeId> PartialEq for BlsSkBytes<S> {
  fn eq(&self, other: &Self) -> bool {
    self.inner.ct_eq(&other.inner).into()
  }
}

impl<S: BlsSchemeId> Hashable for BlsSkBytes<S> {
  type Hash = Hash256;

  fn hash(&self) -> Self::Hash {
    Self::Hash::from_bytes(Sha256d::hash(&self.inner).to_byte_array())
  }
}

#[cfg(test)]
mod tests {
  use super::{BlsSkBytes, BLS_SK_LEN};
  use crate::bls::{BlsScChia, BlsScIetf};
  use crate::prelude::*;

  use dash_types::codec::TypeId;
  use rstest::rstest;

  #[rstest]
  fn redaction() {
    let sk = BlsSkBytes::<BlsScChia>::from_bytes([0xff; BLS_SK_LEN]);
    assert!(!format!("{sk:?}").contains("ff"));

    let sk = BlsSkBytes::<BlsScIetf>::from_bytes([0xab; BLS_SK_LEN]);
    assert!(!format!("{sk}").contains("ab"));
  }

  #[rstest]
  fn distinct_type_ids() {
    assert_ne!(BlsSkBytes::<BlsScChia>::TYPE_ID, BlsSkBytes::<BlsScIetf>::TYPE_ID,);
  }

  #[rstest]
  fn equality() {
    let a = BlsSkBytes::<BlsScChia>::from_bytes([1u8; BLS_SK_LEN]);
    let b = BlsSkBytes::<BlsScChia>::from_bytes([1u8; BLS_SK_LEN]);
    let c = BlsSkBytes::<BlsScChia>::from_bytes([2u8; BLS_SK_LEN]);
    assert_eq!(a, b);
    assert_ne!(a, c);
  }
}
