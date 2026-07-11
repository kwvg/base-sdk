//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Unvalidated byte bags for BLS threshold shares.

use crate::bls::secret_bytes::BlsSkBytes;
use crate::bls::BlsSchemeId;

use dash_num::Hash256;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use core::fmt::{self, Debug, Display, Formatter};
use core::hash;
use core::marker::PhantomData;

const BLS_SIG_SHARE_LEN: usize = 96;

/// Unvalidated secret-key share bytes.
pub struct BlsSkShareBytes<S: BlsSchemeId> {
  id: Hash256,
  sk: BlsSkBytes<S>,
}

impl<S: BlsSchemeId> BlsSkShareBytes<S> {
  /// Construct from an id and secret-key bytes.
  pub fn new(id: Hash256, sk: BlsSkBytes<S>) -> Self {
    Self { id, sk }
  }

  /// Participant identifier.
  pub fn id(&self) -> &Hash256 {
    &self.id
  }

  /// The inner secret-key bytes.
  pub fn sk(&self) -> &BlsSkBytes<S> {
    &self.sk
  }
}

impl<S: BlsSchemeId> Clone for BlsSkShareBytes<S> {
  fn clone(&self) -> Self {
    Self {
      id: self.id,
      sk: self.sk.clone(),
    }
  }
}

impl<S: BlsSchemeId> Debug for BlsSkShareBytes<S> {
  fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
    write!(f, "BlsSkShareBytes<{}>(id={:?})", S::LABEL, self.id)
  }
}

impl<S: BlsSchemeId> Display for BlsSkShareBytes<S> {
  fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
    write!(f, "BlsSkShareBytes<{}>(id={})", S::LABEL, self.id)
  }
}

impl<S: BlsSchemeId> PartialEq for BlsSkShareBytes<S> {
  fn eq(&self, other: &Self) -> bool {
    self.id == other.id && self.sk == other.sk
  }
}

impl<S: BlsSchemeId> Eq for BlsSkShareBytes<S> {}

/// Unvalidated signature share bytes.
pub struct BlsSigShareBytes<S: BlsSchemeId> {
  id: Hash256,
  sig: [u8; BLS_SIG_SHARE_LEN],
  _scheme: PhantomData<S>,
}

impl<S: BlsSchemeId> BlsSigShareBytes<S> {
  /// Construct from an id and signature bytes.
  pub fn new(id: Hash256, sig: [u8; BLS_SIG_SHARE_LEN]) -> Self {
    Self {
      id,
      sig,
      _scheme: PhantomData,
    }
  }

  /// Participant identifier.
  pub fn id(&self) -> &Hash256 {
    &self.id
  }

  /// The inner signature bytes.
  pub fn sig(&self) -> &[u8; BLS_SIG_SHARE_LEN] {
    &self.sig
  }

  /// Copies out the signature bytes in a zeroizing wrapper.
  pub fn to_sig_bytes(&self) -> Zeroizing<[u8; BLS_SIG_SHARE_LEN]> {
    Zeroizing::new(self.sig)
  }
}

impl<S: BlsSchemeId> Clone for BlsSigShareBytes<S> {
  fn clone(&self) -> Self {
    Self {
      id: self.id,
      sig: self.sig,
      _scheme: PhantomData,
    }
  }
}

impl<S: BlsSchemeId> Zeroize for BlsSigShareBytes<S> {
  fn zeroize(&mut self) {
    self.sig.zeroize();
  }
}

impl<S: BlsSchemeId> Drop for BlsSigShareBytes<S> {
  fn drop(&mut self) {
    self.zeroize();
  }
}

impl<S: BlsSchemeId> ZeroizeOnDrop for BlsSigShareBytes<S> {}

impl<S: BlsSchemeId> Debug for BlsSigShareBytes<S> {
  fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
    write!(f, "BlsSigShareBytes<{}>(id={:?})", S::LABEL, self.id)
  }
}

impl<S: BlsSchemeId> Display for BlsSigShareBytes<S> {
  fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
    write!(f, "BlsSigShareBytes<{}>(id={})", S::LABEL, self.id)
  }
}

impl<S: BlsSchemeId> PartialEq for BlsSigShareBytes<S> {
  fn eq(&self, other: &Self) -> bool {
    self.id == other.id && bool::from(self.sig.ct_eq(&other.sig))
  }
}

impl<S: BlsSchemeId> Eq for BlsSigShareBytes<S> {}

impl<S: BlsSchemeId> hash::Hash for BlsSigShareBytes<S> {
  fn hash<H: hash::Hasher>(&self, state: &mut H) {
    self.id.hash(state);
    self.sig.hash(state);
  }
}
