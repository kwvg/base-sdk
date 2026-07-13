//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Unvalidated byte bags for BLS threshold shares.

use crate::bls::secret_bytes::BlsSkBytes;
use crate::bls::sig_bytes::BlsSigBytes;
use crate::bls::BlsSchemeId;

use dash_num::Hash256;

use core::fmt::{Debug, Display, Formatter, Result as FmtResult};
use core::hash::{Hash, Hasher};
use core::marker::PhantomData;

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
  fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
    write!(f, "BlsSkShareBytes<{}>(id={:?})", S::LABEL, self.id)
  }
}

impl<S: BlsSchemeId> Display for BlsSkShareBytes<S> {
  fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
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
  sig: BlsSigBytes<S>,
  _scheme: PhantomData<S>,
}

impl<S: BlsSchemeId> BlsSigShareBytes<S> {
  /// Construct from an id and signature bytes.
  pub fn new(id: Hash256, sig: BlsSigBytes<S>) -> Self {
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
  pub fn sig(&self) -> &BlsSigBytes<S> {
    &self.sig
  }
}

impl<S: BlsSchemeId> Clone for BlsSigShareBytes<S> {
  fn clone(&self) -> Self {
    *self
  }
}

impl<S: BlsSchemeId> Copy for BlsSigShareBytes<S> {}

impl<S: BlsSchemeId> Debug for BlsSigShareBytes<S> {
  fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
    write!(f, "BlsSigShareBytes<{}>(id={:?})", S::LABEL, self.id)
  }
}

impl<S: BlsSchemeId> Display for BlsSigShareBytes<S> {
  fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
    write!(f, "BlsSigShareBytes<{}>(id={})", S::LABEL, self.id)
  }
}

impl<S: BlsSchemeId> PartialEq for BlsSigShareBytes<S> {
  fn eq(&self, other: &Self) -> bool {
    self.id == other.id && self.sig == other.sig
  }
}

impl<S: BlsSchemeId> Eq for BlsSigShareBytes<S> {}

impl<S: BlsSchemeId> Hash for BlsSigShareBytes<S> {
  fn hash<H: Hasher>(&self, state: &mut H) {
    self.id.hash(state);
    self.sig.as_bytes().hash(state);
  }
}
