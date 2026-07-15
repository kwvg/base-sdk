//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Runtime scheme dispatch over dash-pkc's compile-time BLS types.

use alloc::borrow::Cow;
use alloc::vec::Vec;

use dash_num::Hash256;
use dash_pkc::bls::{BlsError, BlsPublicKey, BlsScChia, BlsScIetf, BlsSecretKey, BlsSignature};
use rand_core::{impls, RngCore};

type ChiaPk = BlsPublicKey<BlsScChia>;
type IetfPk = BlsPublicKey<BlsScIetf>;
type ChiaSig = BlsSignature<BlsScChia>;
type IetfSig = BlsSignature<BlsScIetf>;
type IetfSk = BlsSecretKey<BlsScIetf>;

/// Scheme-tagged public key. Dash Core selects legacy vs basic at
/// runtime, dash-pkc at compile time; this enum carries whichever
/// monomorphization the element was parsed under.
#[derive(Debug)]
pub(crate) enum PkImpl {
  Legacy(ChiaPk),
  Basic(IetfPk),
}

impl PkImpl {
  fn as_legacy(&self) -> Result<Cow<'_, ChiaPk>, BlsError> {
    match self {
      PkImpl::Legacy(pk) => Ok(Cow::Borrowed(pk)),
      PkImpl::Basic(pk) => Ok(Cow::Owned(pk.convert()?)),
    }
  }

  fn as_basic(&self) -> Result<Cow<'_, IetfPk>, BlsError> {
    match self {
      PkImpl::Legacy(pk) => Ok(Cow::Owned(pk.convert()?)),
      PkImpl::Basic(pk) => Ok(Cow::Borrowed(pk)),
    }
  }
}

impl Clone for PkImpl {
  fn clone(&self) -> Self {
    match self {
      PkImpl::Legacy(pk) => PkImpl::Legacy(pk.clone()),
      PkImpl::Basic(pk) => PkImpl::Basic(pk.clone()),
    }
  }
}

/// Scheme-tagged signature; see [`PkImpl`].
#[derive(Debug)]
pub(crate) enum SigImpl {
  Legacy(ChiaSig),
  Basic(IetfSig),
}

impl SigImpl {
  fn as_legacy(&self) -> Result<Cow<'_, ChiaSig>, BlsError> {
    match self {
      SigImpl::Legacy(sig) => Ok(Cow::Borrowed(sig)),
      SigImpl::Basic(sig) => Ok(Cow::Owned(sig.convert()?)),
    }
  }

  fn as_basic(&self) -> Result<Cow<'_, IetfSig>, BlsError> {
    match self {
      SigImpl::Legacy(sig) => Ok(Cow::Owned(sig.convert()?)),
      SigImpl::Basic(sig) => Ok(Cow::Borrowed(sig)),
    }
  }
}

impl Clone for SigImpl {
  fn clone(&self) -> Self {
    match self {
      SigImpl::Legacy(sig) => SigImpl::Legacy(sig.clone()),
      SigImpl::Basic(sig) => SigImpl::Basic(sig.clone()),
    }
  }
}

// Borrow elements already in the requested representation and
// convert only mismatched ones; hot paths never clone.
fn pks_to_legacy(pks: &[PkImpl]) -> Result<Vec<Cow<'_, ChiaPk>>, BlsError> {
  pks.iter().map(PkImpl::as_legacy).collect()
}

fn pks_to_basic(pks: &[PkImpl]) -> Result<Vec<Cow<'_, IetfPk>>, BlsError> {
  pks.iter().map(PkImpl::as_basic).collect()
}

fn sigs_to_legacy(sigs: &[SigImpl]) -> Result<Vec<Cow<'_, ChiaSig>>, BlsError> {
  sigs.iter().map(SigImpl::as_legacy).collect()
}

fn sigs_to_basic(sigs: &[SigImpl]) -> Result<Vec<Cow<'_, IetfSig>>, BlsError> {
  sigs.iter().map(SigImpl::as_basic).collect()
}

fn id_from_slice(bytes: &[u8]) -> Result<Hash256, ffi::PkcError> {
  let arr: [u8; 32] = bytes.try_into().map_err(|_| ffi::PkcError::InvalidLength)?;
  Ok(Hash256::from_bytes(arr))
}

/// RngCore over caller-provided entropy so the library never
/// sources randomness itself. Exhaustion is recorded instead of
/// panicking; callers must check [`SliceRng::exhausted`].
struct SliceRng<'a> {
  data: &'a [u8],
  exhausted: bool,
}

impl<'a> SliceRng<'a> {
  fn new(data: &'a [u8]) -> Self {
    Self { data, exhausted: false }
  }
}

impl RngCore for SliceRng<'_> {
  fn next_u32(&mut self) -> u32 {
    impls::next_u32_via_fill(self)
  }

  fn next_u64(&mut self) -> u64 {
    impls::next_u64_via_fill(self)
  }

  fn fill_bytes(&mut self, dest: &mut [u8]) {
    if self.data.len() < dest.len() {
      self.exhausted = true;
      dest.fill(0);
      return;
    }
    let (head, tail) = self.data.split_at(dest.len());
    dest.copy_from_slice(head);
    self.data = tail;
  }

  fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
    self.fill_bytes(dest);
    Ok(())
  }
}

/// Entropy required by one IES encryption (32-byte ephemeral key
/// IKM plus 32-byte IV seed).
const IES_ENTROPY_LEN: usize = 64;

/// Entropy a session consumes at creation (keyed-hash material).
const SESSION_ENTROPY_LEN: usize = 32;

/// Bounded FIFO map used for all session caches. All cached values
/// are pure functions of their keys, so eviction never affects
/// correctness, only hit rate.
struct BoundedCache<K: Ord + Clone, V: Clone> {
  map: alloc::collections::BTreeMap<K, V>,
  order: alloc::collections::VecDeque<K>,
  cap: usize,
}

impl<K: Ord + Clone, V: Clone> BoundedCache<K, V> {
  fn new(cap: usize) -> Self {
    Self {
      map: alloc::collections::BTreeMap::new(),
      order: alloc::collections::VecDeque::new(),
      cap,
    }
  }

  fn get(&self, key: &K) -> Option<V> {
    self.map.get(key).cloned()
  }

  fn insert(&mut self, key: K, value: V) {
    if self.map.insert(key.clone(), value).is_none() {
      self.order.push_back(key);
      if self.order.len() > self.cap {
        if let Some(evicted) = self.order.pop_front() {
          self.map.remove(&evicted);
        }
      }
    }
  }
}

type MsgPointLegacy = dash_pkc::bls::BlsMessagePoint<BlsScChia>;
type MsgPointBasic = dash_pkc::bls::BlsMessagePoint<BlsScIetf>;

/// Program-lifetime cache state owned by the embedding application
/// (Dash Core's `g_bls_session`); see `ffi::Session`.
pub(crate) struct SessionState {
  // Keyed-hash material for content-addressed caches; consumed
  // once the verification-result cache lands.
  #[expect(dead_code, reason = "reserved for keyed result caching")]
  entropy: [u8; SESSION_ENTROPY_LEN],
  msg_points_legacy: spin::Mutex<BoundedCache<[u8; 32], MsgPointLegacy>>,
  msg_points_basic: spin::Mutex<BoundedCache<[u8; 32], MsgPointBasic>>,
}

impl SessionState {
  fn new(entropy: [u8; SESSION_ENTROPY_LEN]) -> Self {
    Self {
      entropy,
      msg_points_legacy: spin::Mutex::new(BoundedCache::new(4096)),
      msg_points_basic: spin::Mutex::new(BoundedCache::new(4096)),
    }
  }

  fn msg_point_legacy(&self, msg32: &[u8; 32]) -> Result<MsgPointLegacy, BlsError> {
    if let Some(mp) = self.msg_points_legacy.lock().get(msg32) {
      return Ok(mp);
    }
    let mp = MsgPointLegacy::hash(msg32)?;
    self.msg_points_legacy.lock().insert(*msg32, mp.clone());
    Ok(mp)
  }

  fn msg_point_basic(&self, msg32: &[u8; 32]) -> Result<MsgPointBasic, BlsError> {
    if let Some(mp) = self.msg_points_basic.lock().get(msg32) {
      return Ok(mp);
    }
    let mp = MsgPointBasic::hash(msg32)?;
    self.msg_points_basic.lock().insert(*msg32, mp.clone());
    Ok(mp)
  }
}

impl core::fmt::Debug for SessionState {
  fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
    write!(f, "SessionState(..)")
  }
}

impl From<BlsError> for ffi::PkcError {
  fn from(err: BlsError) -> Self {
    match err {
      BlsError::InvalidKeyMaterial => ffi::PkcError::InvalidKeyMaterial,
      BlsError::InvalidSecretKey => ffi::PkcError::InvalidSecretKey,
      BlsError::InvalidPublicKey => ffi::PkcError::InvalidPublicKey,
      BlsError::InvalidSignature => ffi::PkcError::InvalidSignature,
      BlsError::VerifyFailed => ffi::PkcError::VerifyFailed,
      BlsError::InvalidMessageLength => ffi::PkcError::InvalidMessageLength,
      BlsError::EmptyAggregation => ffi::PkcError::EmptyAggregation,
      BlsError::CountMismatch => ffi::PkcError::CountMismatch,
      BlsError::ThresholdTooLarge => ffi::PkcError::ThresholdTooLarge,
      BlsError::InsufficientShares => ffi::PkcError::InsufficientShares,
      BlsError::DuplicateShareId => ffi::PkcError::DuplicateShareId,
      BlsError::InvalidShareId => ffi::PkcError::InvalidShareId,
      BlsError::InvalidVerificationVector => ffi::PkcError::InvalidVerificationVector,
      BlsError::DuplicateMessage => ffi::PkcError::DuplicateMessage,
      BlsError::ShareIdMismatch => ffi::PkcError::ShareIdMismatch,
      BlsError::InvalidPlaintextLength => ffi::PkcError::InvalidPlaintextLength,
      BlsError::DecryptionFailed => ffi::PkcError::DecryptionFailed,
      BlsError::IndexOutOfRange => ffi::PkcError::IndexOutOfRange,
      BlsError::UnsupportedScheme => ffi::PkcError::UnsupportedScheme,
    }
  }
}

#[diplomat::bridge]
pub mod ffi {
  use super::{
    id_from_slice, pks_to_basic, pks_to_legacy, sigs_to_basic, sigs_to_legacy, ChiaPk, ChiaSig, IetfPk, IetfSig,
    IetfSk, PkImpl, SessionState, SigImpl, SliceRng, IES_ENTROPY_LEN, SESSION_ENTROPY_LEN,
  };

  use alloc::boxed::Box;
  use alloc::vec::Vec;
  use dash_num::Hash256;
  use dash_pkc::bls::{BlsIesBytes, BlsIesMultiBytes, BlsScChia, BlsScIetf, BlsSigShare, BlsSkBytes};
  use dash_types::codec::BaseCodec;

  /// Serialization and signing scheme: `Legacy` is Dash's
  /// pre-basic-scheme (Chia) format, `Basic` the IETF format.
  #[diplomat::attr(auto, namespace = "dash_pkc::ffi")]
  #[derive(Debug, PartialEq, Eq)]
  pub enum Scheme {
    Legacy,
    Basic,
  }

  /// Error codes mirroring `dash_pkc::bls::BlsError`, plus FFI
  /// buffer and encoding failures.
  #[diplomat::attr(auto, namespace = "dash_pkc::ffi")]
  #[derive(Debug, PartialEq, Eq)]
  pub enum PkcError {
    InvalidKeyMaterial,
    InvalidSecretKey,
    InvalidPublicKey,
    InvalidSignature,
    VerifyFailed,
    InvalidMessageLength,
    EmptyAggregation,
    CountMismatch,
    ThresholdTooLarge,
    InsufficientShares,
    DuplicateShareId,
    InvalidShareId,
    InvalidVerificationVector,
    DuplicateMessage,
    ShareIdMismatch,
    InvalidPlaintextLength,
    DecryptionFailed,
    IndexOutOfRange,
    UnsupportedScheme,
    InvalidLength,
    InvalidEncoding,
    InsufficientEntropy,
    InternalError,
  }

  /// A BLS12-381 secret key (32 bytes, big-endian scalar).
  ///
  /// Secret scalars are scheme independent; scheme selection
  /// happens per operation (`sign`, `public_key`).
  #[diplomat::opaque]
  #[diplomat::attr(auto, namespace = "dash_pkc::ffi")]
  #[derive(Debug)]
  pub struct SecretKey(pub(crate) IetfSk);

  /// A G1 public key (48 bytes compressed), scheme-tagged.
  #[diplomat::opaque]
  #[diplomat::attr(auto, namespace = "dash_pkc::ffi")]
  #[derive(Debug)]
  pub struct PublicKey(pub(crate) PkImpl);

  /// A G2 signature (96 bytes compressed), scheme-tagged.
  #[diplomat::opaque]
  #[diplomat::attr(auto, namespace = "dash_pkc::ffi")]
  #[derive(Debug)]
  pub struct Signature(pub(crate) SigImpl);

  /// Builder collection of secret keys for aggregate operations.
  #[diplomat::opaque_mut]
  #[diplomat::attr(auto, namespace = "dash_pkc::ffi")]
  #[derive(Debug)]
  pub struct SecretKeyVec(pub(crate) Vec<IetfSk>);

  /// Builder collection of public keys for aggregate operations.
  #[diplomat::opaque_mut]
  #[diplomat::attr(auto, namespace = "dash_pkc::ffi")]
  #[derive(Debug)]
  pub struct PublicKeyVec(pub(crate) Vec<PkImpl>);

  /// Builder collection of signatures for aggregate operations.
  #[diplomat::opaque_mut]
  #[diplomat::attr(auto, namespace = "dash_pkc::ffi")]
  #[derive(Debug)]
  pub struct SignatureVec(pub(crate) Vec<SigImpl>);

  /// Builder collection of 32-byte participant ids.
  #[diplomat::opaque_mut]
  #[diplomat::attr(auto, namespace = "dash_pkc::ffi")]
  #[derive(Debug)]
  pub struct IdVec(pub(crate) Vec<Hash256>);

  /// Builder collection of arbitrary-length messages.
  #[diplomat::opaque_mut]
  #[diplomat::attr(auto, namespace = "dash_pkc::ffi")]
  #[derive(Debug)]
  pub struct MessageVec(pub(crate) Vec<Vec<u8>>);

  /// A single-recipient BLS-IES encrypted blob in Dash Core's
  /// on-wire format.
  #[diplomat::opaque]
  #[diplomat::attr(auto, namespace = "dash_pkc::ffi")]
  #[derive(Debug)]
  pub struct IesBlob(pub(crate) BlsIesBytes);

  /// A multi-recipient BLS-IES encrypted blob in Dash Core's
  /// on-wire format.
  #[diplomat::opaque]
  #[diplomat::attr(auto, namespace = "dash_pkc::ffi")]
  #[derive(Debug)]
  pub struct IesMultiBlob(pub(crate) BlsIesMultiBytes);

  impl SecretKey {
    /// Parse a 32-byte big-endian scalar; rejects zero and values
    /// not below the group order.
    pub fn from_bytes(bytes: &[u8]) -> Result<Box<SecretKey>, PkcError> {
      let arr: &[u8; 32] = bytes.try_into().map_err(|_| PkcError::InvalidLength)?;
      Ok(Box::new(SecretKey(IetfSk::from_bytes(arr)?)))
    }

    /// Derive a key from at least 32 bytes of seed material
    /// (dashbls EIP-2333 v3 KeyGen).
    pub fn generate(ikm: &[u8]) -> Result<Box<SecretKey>, PkcError> {
      Ok(Box::new(SecretKey(IetfSk::generate(ikm)?)))
    }

    /// Write the 32-byte big-endian scalar into `out`.
    pub fn to_bytes(&self, out: &mut [u8]) -> Result<(), PkcError> {
      if out.len() != 32 {
        return Err(PkcError::InvalidLength);
      }
      out.copy_from_slice(self.0.to_bytes().as_ref());
      Ok(())
    }

    /// Derive the public key, tagged with `scheme`.
    pub fn public_key(&self, scheme: Scheme) -> Result<Box<PublicKey>, PkcError> {
      let pk = match scheme {
        Scheme::Legacy => PkImpl::Legacy(self.0.convert::<BlsScChia>()?.public_key()),
        Scheme::Basic => PkImpl::Basic(self.0.public_key()),
      };
      Ok(Box::new(PublicKey(pk)))
    }

    /// Sign `msg` under `scheme`. Legacy signing requires a
    /// 32-byte message (a hash), matching dashbls.
    pub fn sign(&self, msg: &[u8], scheme: Scheme) -> Result<Box<Signature>, PkcError> {
      let sig = match scheme {
        Scheme::Legacy => SigImpl::Legacy(self.0.convert::<BlsScChia>()?.sign(msg)?),
        Scheme::Basic => SigImpl::Basic(self.0.sign(msg)?),
      };
      Ok(Box::new(Signature(sig)))
    }

    /// Sum the collected keys mod the group order (dashbls
    /// `PrivateKey::Aggregate`).
    pub fn aggregate(keys: &SecretKeyVec) -> Result<Box<SecretKey>, PkcError> {
      let refs: Vec<&IetfSk> = keys.0.iter().collect();
      Ok(Box::new(SecretKey(IetfSk::aggregate(&refs)?)))
    }

    /// Evaluate the secret polynomial `masters` at the 32-byte
    /// participant `id` (dashbls `Threshold::PrivateKeyShare`).
    pub fn derive_share(masters: &SecretKeyVec, id: &[u8]) -> Result<Box<SecretKey>, PkcError> {
      let id = id_from_slice(id)?;
      let refs: Vec<&IetfSk> = masters.0.iter().collect();
      Ok(Box::new(SecretKey(IetfSk::derive_share(&refs, &id)?)))
    }

    /// Diffie-Hellman exchange `self * peer`; the result carries
    /// the peer's scheme tag.
    pub fn dh_exchange(&self, peer: &PublicKey) -> Result<Box<PublicKey>, PkcError> {
      let pk = match &peer.0 {
        PkImpl::Legacy(pk) => PkImpl::Legacy(ChiaPk::dh_exchange(&self.0.convert::<BlsScChia>()?, pk)?),
        PkImpl::Basic(pk) => PkImpl::Basic(IetfPk::dh_exchange(&self.0, pk)?),
      };
      Ok(Box::new(PublicKey(pk)))
    }

    /// Decrypt a single-recipient blob whose ephemeral key was
    /// serialized under `scheme`. `out` must be exactly
    /// `blob.data_len()` bytes (CBC keeps lengths).
    pub fn ies_decrypt(&self, blob: &IesBlob, index: usize, scheme: Scheme, out: &mut [u8]) -> Result<(), PkcError> {
      let plain = match scheme {
        Scheme::Legacy => self.0.convert::<BlsScChia>()?.ies_decrypt(&blob.0, index)?,
        Scheme::Basic => self.0.ies_decrypt(&blob.0, index)?,
      };
      if out.len() != plain.len() {
        return Err(PkcError::InvalidLength);
      }
      out.copy_from_slice(&plain);
      Ok(())
    }

    /// Decrypt one recipient's slot of a multi-recipient blob
    /// whose ephemeral key was serialized under `scheme`. `out`
    /// must be exactly `blob.data_len_at(index)` bytes.
    pub fn ies_decrypt_multi(
      &self,
      blob: &IesMultiBlob,
      index: usize,
      scheme: Scheme,
      out: &mut [u8],
    ) -> Result<(), PkcError> {
      let plain = match scheme {
        Scheme::Legacy => self.0.convert::<BlsScChia>()?.ies_decrypt_multi(&blob.0, index)?,
        Scheme::Basic => self.0.ies_decrypt_multi(&blob.0, index)?,
      };
      if out.len() != plain.len() {
        return Err(PkcError::InvalidLength);
      }
      out.copy_from_slice(&plain);
      Ok(())
    }

    /// Deep copy for C++ value semantics.
    #[diplomat::attr(*, rename = "clone")]
    pub fn boxed_clone(&self) -> Box<SecretKey> {
      Box::new(SecretKey(self.0.clone()))
    }

    /// Constant-time equality.
    pub fn eq(&self, other: &SecretKey) -> bool {
      let a = BlsSkBytes::<BlsScIetf>::from_bytes(*self.0.to_bytes());
      let b = BlsSkBytes::<BlsScIetf>::from_bytes(*other.0.to_bytes());
      a == b
    }
  }

  impl PublicKey {
    /// Parse 48 compressed bytes under `scheme`. Rejects
    /// infinity and non-subgroup points.
    pub fn from_bytes(bytes: &[u8], scheme: Scheme) -> Result<Box<PublicKey>, PkcError> {
      let arr: &[u8; 48] = bytes.try_into().map_err(|_| PkcError::InvalidLength)?;
      let pk = match scheme {
        Scheme::Legacy => PkImpl::Legacy(ChiaPk::from_bytes(arr)?),
        Scheme::Basic => PkImpl::Basic(IetfPk::from_bytes(arr)?),
      };
      Ok(Box::new(PublicKey(pk)))
    }

    /// Write the 48-byte compressed form under `scheme` into
    /// `out`, converting representations when they differ.
    pub fn to_bytes(&self, out: &mut [u8], scheme: Scheme) -> Result<(), PkcError> {
      if out.len() != 48 {
        return Err(PkcError::InvalidLength);
      }
      let bytes = match scheme {
        Scheme::Legacy => self.0.as_legacy()?.to_bytes(),
        Scheme::Basic => self.0.as_basic()?.to_bytes(),
      };
      out.copy_from_slice(&bytes);
      Ok(())
    }

    /// The scheme this element was parsed or derived under.
    pub fn scheme(&self) -> Scheme {
      match self.0 {
        PkImpl::Legacy(_) => Scheme::Legacy,
        PkImpl::Basic(_) => Scheme::Basic,
      }
    }

    /// Deep copy for C++ value semantics.
    #[diplomat::attr(*, rename = "clone")]
    pub fn boxed_clone(&self) -> Box<PublicKey> {
      Box::new(PublicKey(self.0.clone()))
    }

    /// Group element equality across scheme tags.
    pub fn eq(&self, other: &PublicKey) -> bool {
      match (&self.0, &other.0) {
        (PkImpl::Legacy(a), PkImpl::Legacy(b)) => a == b,
        (PkImpl::Basic(a), PkImpl::Basic(b)) => a == b,
        _ => match (self.0.as_basic(), other.0.as_basic()) {
          (Ok(a), Ok(b)) => a == b,
          _ => false,
        },
      }
    }

    /// Sum this key with one other (the hot pairwise-accumulate
    /// path of Dash Core's AggregateInsecure member).
    pub fn aggregate_with(&self, other: &PublicKey, scheme: Scheme) -> Result<Box<PublicKey>, PkcError> {
      let pk = match scheme {
        Scheme::Legacy => {
          let a = self.0.as_legacy()?;
          let b = other.0.as_legacy()?;
          PkImpl::Legacy(ChiaPk::aggregate(&[&a, &b])?)
        }
        Scheme::Basic => {
          let a = self.0.as_basic()?;
          let b = other.0.as_basic()?;
          PkImpl::Basic(IetfPk::aggregate(&[&a, &b])?)
        }
      };
      Ok(Box::new(PublicKey(pk)))
    }

    /// Sum the collected keys (dashbls `CoreMPL::Aggregate`).
    pub fn aggregate(keys: &PublicKeyVec, scheme: Scheme) -> Result<Box<PublicKey>, PkcError> {
      let pk = match scheme {
        Scheme::Legacy => {
          let owned = pks_to_legacy(&keys.0)?;
          let refs: Vec<&ChiaPk> = owned.iter().map(|c| &**c).collect();
          PkImpl::Legacy(ChiaPk::aggregate(&refs)?)
        }
        Scheme::Basic => {
          let owned = pks_to_basic(&keys.0)?;
          let refs: Vec<&IetfPk> = owned.iter().map(|c| &**c).collect();
          PkImpl::Basic(IetfPk::aggregate(&refs)?)
        }
      };
      Ok(Box::new(PublicKey(pk)))
    }

    /// Evaluate the public polynomial `masters` at the 32-byte
    /// participant `id` (dashbls `Threshold::PublicKeyShare`).
    pub fn derive_share(masters: &PublicKeyVec, id: &[u8], scheme: Scheme) -> Result<Box<PublicKey>, PkcError> {
      let id = id_from_slice(id)?;
      let pk = match scheme {
        Scheme::Legacy => {
          let owned = pks_to_legacy(&masters.0)?;
          let refs: Vec<&ChiaPk> = owned.iter().map(|c| &**c).collect();
          PkImpl::Legacy(ChiaPk::derive_share(&refs, &id)?)
        }
        Scheme::Basic => {
          let owned = pks_to_basic(&masters.0)?;
          let refs: Vec<&IetfPk> = owned.iter().map(|c| &**c).collect();
          PkImpl::Basic(IetfPk::derive_share(&refs, &id)?)
        }
      };
      Ok(Box::new(PublicKey(pk)))
    }

    /// BLS-IES encrypt `plaintext` (length a multiple of 16) to
    /// this key. `entropy` must supply at least 64 random bytes.
    pub fn ies_encrypt(&self, plaintext: &[u8], entropy: &[u8]) -> Result<Box<IesBlob>, PkcError> {
      if entropy.len() < IES_ENTROPY_LEN {
        return Err(PkcError::InsufficientEntropy);
      }
      let mut rng = SliceRng::new(entropy);
      let blob = match &self.0 {
        PkImpl::Legacy(pk) => pk.ies_encrypt(plaintext, &mut rng)?,
        PkImpl::Basic(pk) => pk.ies_encrypt(plaintext, &mut rng)?,
      };
      if rng.exhausted {
        return Err(PkcError::InsufficientEntropy);
      }
      Ok(Box::new(IesBlob(blob)))
    }

    /// BLS-IES encrypt one plaintext per recipient under a shared
    /// ephemeral key. `entropy` must supply at least 64 random
    /// bytes.
    pub fn ies_encrypt_multi(
      recipients: &PublicKeyVec,
      plaintexts: &MessageVec,
      entropy: &[u8],
      scheme: Scheme,
    ) -> Result<Box<IesMultiBlob>, PkcError> {
      if entropy.len() < IES_ENTROPY_LEN {
        return Err(PkcError::InsufficientEntropy);
      }
      let mut rng = SliceRng::new(entropy);
      let plain_refs: Vec<&[u8]> = plaintexts.0.iter().map(Vec::as_slice).collect();
      let blob = match scheme {
        Scheme::Legacy => {
          let owned = pks_to_legacy(&recipients.0)?;
          let refs: Vec<&ChiaPk> = owned.iter().map(|c| &**c).collect();
          ChiaPk::ies_encrypt_multi(&refs, &plain_refs, &mut rng)?
        }
        Scheme::Basic => {
          let owned = pks_to_basic(&recipients.0)?;
          let refs: Vec<&IetfPk> = owned.iter().map(|c| &**c).collect();
          IetfPk::ies_encrypt_multi(&refs, &plain_refs, &mut rng)?
        }
      };
      if rng.exhausted {
        return Err(PkcError::InsufficientEntropy);
      }
      Ok(Box::new(IesMultiBlob(blob)))
    }
  }

  impl Signature {
    /// Parse 96 compressed bytes under `scheme`. Rejects
    /// infinity and non-subgroup points.
    pub fn from_bytes(bytes: &[u8], scheme: Scheme) -> Result<Box<Signature>, PkcError> {
      let arr: &[u8; 96] = bytes.try_into().map_err(|_| PkcError::InvalidLength)?;
      let sig = match scheme {
        Scheme::Legacy => SigImpl::Legacy(ChiaSig::from_bytes(arr)?),
        Scheme::Basic => SigImpl::Basic(IetfSig::from_bytes(arr)?),
      };
      Ok(Box::new(Signature(sig)))
    }

    /// Write the 96-byte compressed form under `scheme` into
    /// `out`, converting representations when they differ.
    pub fn to_bytes(&self, out: &mut [u8], scheme: Scheme) -> Result<(), PkcError> {
      if out.len() != 96 {
        return Err(PkcError::InvalidLength);
      }
      let bytes = match scheme {
        Scheme::Legacy => self.0.as_legacy()?.to_bytes(),
        Scheme::Basic => self.0.as_basic()?.to_bytes(),
      };
      out.copy_from_slice(&bytes);
      Ok(())
    }

    /// The scheme this element was parsed or derived under.
    pub fn scheme(&self) -> Scheme {
      match self.0 {
        SigImpl::Legacy(_) => Scheme::Legacy,
        SigImpl::Basic(_) => Scheme::Basic,
      }
    }

    /// Deep copy for C++ value semantics.
    #[diplomat::attr(*, rename = "clone")]
    pub fn boxed_clone(&self) -> Box<Signature> {
      Box::new(Signature(self.0.clone()))
    }

    /// Group element equality across scheme tags.
    pub fn eq(&self, other: &Signature) -> bool {
      match (&self.0, &other.0) {
        (SigImpl::Legacy(a), SigImpl::Legacy(b)) => a == b,
        (SigImpl::Basic(a), SigImpl::Basic(b)) => a == b,
        _ => match (self.0.as_basic(), other.0.as_basic()) {
          (Ok(a), Ok(b)) => a == b,
          _ => false,
        },
      }
    }

    /// Verify against a single key and message under `scheme`
    /// (dashbls `CoreMPL::Verify`).
    pub fn verify(&self, msg: &[u8], pk: &PublicKey, scheme: Scheme) -> Result<(), PkcError> {
      match scheme {
        Scheme::Legacy => Ok(self.0.as_legacy()?.verify(msg, pk.0.as_legacy()?.as_ref())?),
        Scheme::Basic => Ok(self.0.as_basic()?.verify(msg, pk.0.as_basic()?.as_ref())?),
      }
    }

    /// Sum this signature with one other (the hot
    /// pairwise-accumulate path of Dash Core's AggregateInsecure).
    pub fn aggregate_with(&self, other: &Signature, scheme: Scheme) -> Result<Box<Signature>, PkcError> {
      let sig = match scheme {
        Scheme::Legacy => {
          let a = self.0.as_legacy()?;
          let b = other.0.as_legacy()?;
          SigImpl::Legacy(ChiaSig::aggregate(&[&a, &b])?)
        }
        Scheme::Basic => {
          let a = self.0.as_basic()?;
          let b = other.0.as_basic()?;
          SigImpl::Basic(IetfSig::aggregate(&[&a, &b])?)
        }
      };
      Ok(Box::new(Signature(sig)))
    }

    /// Sum the collected signatures (dashbls
    /// `CoreMPL::Aggregate`).
    pub fn aggregate(sigs: &SignatureVec, scheme: Scheme) -> Result<Box<Signature>, PkcError> {
      let sig = match scheme {
        Scheme::Legacy => {
          let owned = sigs_to_legacy(&sigs.0)?;
          let refs: Vec<&ChiaSig> = owned.iter().map(|c| &**c).collect();
          SigImpl::Legacy(ChiaSig::aggregate(&refs)?)
        }
        Scheme::Basic => {
          let owned = sigs_to_basic(&sigs.0)?;
          let refs: Vec<&IetfSig> = owned.iter().map(|c| &**c).collect();
          SigImpl::Basic(IetfSig::aggregate(&refs)?)
        }
      };
      Ok(Box::new(Signature(sig)))
    }

    /// Aggregate same-message signatures with public-key-weighted
    /// delinearization (dashbls `CoreMPL::AggregateSecure`).
    pub fn aggregate_secure(
      sigs: &SignatureVec,
      pks: &PublicKeyVec,
      scheme: Scheme,
    ) -> Result<Box<Signature>, PkcError> {
      let sig = match scheme {
        Scheme::Legacy => {
          let owned_sigs = sigs_to_legacy(&sigs.0)?;
          let owned_pks = pks_to_legacy(&pks.0)?;
          let sig_refs: Vec<&ChiaSig> = owned_sigs.iter().map(|c| &**c).collect();
          let pk_refs: Vec<&ChiaPk> = owned_pks.iter().map(|c| &**c).collect();
          SigImpl::Legacy(ChiaSig::aggregate_secure(&sig_refs, &pk_refs)?)
        }
        Scheme::Basic => {
          let owned_sigs = sigs_to_basic(&sigs.0)?;
          let owned_pks = pks_to_basic(&pks.0)?;
          let sig_refs: Vec<&IetfSig> = owned_sigs.iter().map(|c| &**c).collect();
          let pk_refs: Vec<&IetfPk> = owned_pks.iter().map(|c| &**c).collect();
          SigImpl::Basic(IetfSig::aggregate_secure(&sig_refs, &pk_refs)?)
        }
      };
      Ok(Box::new(Signature(sig)))
    }

    /// Verify a secure-aggregated same-message signature (dashbls
    /// `CoreMPL::VerifySecure`).
    pub fn verify_secure(&self, pks: &PublicKeyVec, msg: &[u8], scheme: Scheme) -> Result<(), PkcError> {
      match scheme {
        Scheme::Legacy => {
          let owned = pks_to_legacy(&pks.0)?;
          let refs: Vec<&ChiaPk> = owned.iter().map(|c| &**c).collect();
          Ok(self.0.as_legacy()?.secure_verify_aggregates(msg, &refs)?)
        }
        Scheme::Basic => {
          let owned = pks_to_basic(&pks.0)?;
          let refs: Vec<&IetfPk> = owned.iter().map(|c| &**c).collect();
          Ok(self.0.as_basic()?.secure_verify_aggregates(msg, &refs)?)
        }
      }
    }

    /// Verify an aggregate over per-signer messages (dashbls
    /// `CoreMPL::AggregateVerify`). Basic enforces distinct
    /// messages; legacy does not, matching dashbls.
    pub fn verify_aggregated(&self, msgs: &MessageVec, pks: &PublicKeyVec, scheme: Scheme) -> Result<(), PkcError> {
      let msg_refs: Vec<&[u8]> = msgs.0.iter().map(Vec::as_slice).collect();
      match scheme {
        Scheme::Legacy => {
          let owned = pks_to_legacy(&pks.0)?;
          let refs: Vec<&ChiaPk> = owned.iter().map(|c| &**c).collect();
          Ok(self.0.as_legacy()?.verify_aggregates(&msg_refs, &refs)?)
        }
        Scheme::Basic => {
          let owned = pks_to_basic(&pks.0)?;
          let refs: Vec<&IetfPk> = owned.iter().map(|c| &**c).collect();
          Ok(self.0.as_basic()?.verify_aggregates(&msg_refs, &refs)?)
        }
      }
    }

    /// Subtract `other` from this aggregate: `self + (-other)`
    /// (Dash Core `CBLSSignature::SubInsecure`).
    pub fn sub_insecure(&self, other: &Signature) -> Result<Box<Signature>, PkcError> {
      let sig = match &self.0 {
        SigImpl::Legacy(sig) => SigImpl::Legacy(sig.sub_insecure(other.0.as_legacy()?.as_ref())?),
        SigImpl::Basic(sig) => SigImpl::Basic(sig.sub_insecure(other.0.as_basic()?.as_ref())?),
      };
      Ok(Box::new(Signature(sig)))
    }

    /// Recover a threshold signature from id-tagged shares via
    /// Lagrange interpolation (dashbls
    /// `Threshold::SignatureRecover`).
    pub fn recover(sigs: &SignatureVec, ids: &IdVec, scheme: Scheme) -> Result<Box<Signature>, PkcError> {
      if sigs.0.len() != ids.0.len() {
        return Err(PkcError::CountMismatch);
      }
      let sig = match scheme {
        Scheme::Legacy => {
          let owned = sigs_to_legacy(&sigs.0)?;
          let shares: Vec<BlsSigShare<BlsScChia>> = owned
            .into_iter()
            .zip(ids.0.iter())
            .map(|(sig, id)| BlsSigShare::new(*id, sig.into_owned()))
            .collect();
          let refs: Vec<&BlsSigShare<BlsScChia>> = shares.iter().collect();
          SigImpl::Legacy(ChiaSig::recover(&refs)?)
        }
        Scheme::Basic => {
          let owned = sigs_to_basic(&sigs.0)?;
          let shares: Vec<BlsSigShare<BlsScIetf>> = owned
            .into_iter()
            .zip(ids.0.iter())
            .map(|(sig, id)| BlsSigShare::new(*id, sig.into_owned()))
            .collect();
          let refs: Vec<&BlsSigShare<BlsScIetf>> = shares.iter().collect();
          SigImpl::Basic(IetfSig::recover(&refs)?)
        }
      };
      Ok(Box::new(Signature(sig)))
    }
  }

  impl SecretKeyVec {
    pub fn new() -> Box<SecretKeyVec> {
      Box::new(SecretKeyVec(Vec::new()))
    }

    pub fn push(&mut self, key: &SecretKey) {
      self.0.push(key.0.clone());
    }

    pub fn len(&self) -> usize {
      self.0.len()
    }
  }

  impl PublicKeyVec {
    pub fn new() -> Box<PublicKeyVec> {
      Box::new(PublicKeyVec(Vec::new()))
    }

    pub fn push(&mut self, key: &PublicKey) {
      self.0.push(key.0.clone());
    }

    pub fn len(&self) -> usize {
      self.0.len()
    }
  }

  impl SignatureVec {
    pub fn new() -> Box<SignatureVec> {
      Box::new(SignatureVec(Vec::new()))
    }

    pub fn push(&mut self, sig: &Signature) {
      self.0.push(sig.0.clone());
    }

    pub fn len(&self) -> usize {
      self.0.len()
    }
  }

  impl IdVec {
    pub fn new() -> Box<IdVec> {
      Box::new(IdVec(Vec::new()))
    }

    /// Append a 32-byte participant id.
    pub fn push(&mut self, id: &[u8]) -> Result<(), PkcError> {
      self.0.push(id_from_slice(id)?);
      Ok(())
    }

    pub fn len(&self) -> usize {
      self.0.len()
    }
  }

  impl MessageVec {
    pub fn new() -> Box<MessageVec> {
      Box::new(MessageVec(Vec::new()))
    }

    pub fn push(&mut self, msg: &[u8]) {
      self.0.push(msg.to_vec());
    }

    pub fn len(&self) -> usize {
      self.0.len()
    }
  }

  impl IesBlob {
    /// Parse a consensus-encoded blob, rejecting trailing bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Box<IesBlob>, PkcError> {
      let mut cursor = bytes;
      let blob = BlsIesBytes::decode(&mut cursor).map_err(|_| PkcError::InvalidEncoding)?;
      if !cursor.is_empty() {
        return Err(PkcError::InvalidEncoding);
      }
      Ok(Box::new(IesBlob(blob)))
    }

    /// Length of the consensus encoding in bytes.
    pub fn encoded_len(&self) -> usize {
      let mut buf = Vec::new();
      self.0.encode(&mut buf);
      buf.len()
    }

    /// Write the consensus encoding into `out` (exactly
    /// `encoded_len()` bytes).
    pub fn to_bytes(&self, out: &mut [u8]) -> Result<(), PkcError> {
      let mut buf = Vec::new();
      self.0.encode(&mut buf);
      if out.len() != buf.len() {
        return Err(PkcError::InvalidLength);
      }
      out.copy_from_slice(&buf);
      Ok(())
    }

    /// Ciphertext (= plaintext) length in bytes.
    pub fn data_len(&self) -> usize {
      self.0.data().len()
    }
  }

  impl IesMultiBlob {
    /// Parse a consensus-encoded blob, rejecting trailing bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Box<IesMultiBlob>, PkcError> {
      let mut cursor = bytes;
      let blob = BlsIesMultiBytes::decode(&mut cursor).map_err(|_| PkcError::InvalidEncoding)?;
      if !cursor.is_empty() {
        return Err(PkcError::InvalidEncoding);
      }
      Ok(Box::new(IesMultiBlob(blob)))
    }

    /// Length of the consensus encoding in bytes.
    pub fn encoded_len(&self) -> usize {
      let mut buf = Vec::new();
      self.0.encode(&mut buf);
      buf.len()
    }

    /// Write the consensus encoding into `out` (exactly
    /// `encoded_len()` bytes).
    pub fn to_bytes(&self, out: &mut [u8]) -> Result<(), PkcError> {
      let mut buf = Vec::new();
      self.0.encode(&mut buf);
      if out.len() != buf.len() {
        return Err(PkcError::InvalidLength);
      }
      out.copy_from_slice(&buf);
      Ok(())
    }

    /// Number of recipient slots.
    pub fn blob_count(&self) -> usize {
      self.0.blobs().len()
    }

    /// Ciphertext (= plaintext) length of one recipient slot.
    pub fn data_len_at(&self, index: usize) -> Result<usize, PkcError> {
      self.0.blobs().get(index).map(Vec::len).ok_or(PkcError::IndexOutOfRange)
    }
  }

  /// Program-lifetime crypto context (libsecp256k1-style): owns all
  /// runtime caches and the keyed-hash entropy. Create once at
  /// application init with strong entropy; operations routed
  /// through a session use its caches, plain operations never do.
  #[diplomat::opaque]
  #[diplomat::attr(auto, namespace = "dash_pkc::ffi")]
  #[derive(Debug)]
  pub struct Session(pub(crate) SessionState);

  impl Session {
    /// Create a session from at least 32 bytes of entropy.
    pub fn create(entropy: &[u8]) -> Result<Box<Session>, PkcError> {
      let arr: [u8; SESSION_ENTROPY_LEN] = entropy
        .get(..SESSION_ENTROPY_LEN)
        .and_then(|s| s.try_into().ok())
        .ok_or(PkcError::InsufficientEntropy)?;
      Ok(Box::new(Session(SessionState::new(arr))))
    }

    /// As `Signature::verify`, using the session's hash-to-G2
    /// cache for 32-byte messages.
    pub fn verify(&self, sig: &Signature, msg: &[u8], pk: &PublicKey, scheme: Scheme) -> Result<(), PkcError> {
      if let Ok(msg32) = <&[u8; 32]>::try_from(msg) {
        return match scheme {
          Scheme::Legacy => {
            let mp = self.0.msg_point_legacy(msg32)?;
            Ok(sig.0.as_legacy()?.verify_prehashed(&mp, pk.0.as_legacy()?.as_ref())?)
          }
          Scheme::Basic => {
            let mp = self.0.msg_point_basic(msg32)?;
            Ok(sig.0.as_basic()?.verify_prehashed(&mp, pk.0.as_basic()?.as_ref())?)
          }
        };
      }
      sig.verify(msg, pk, scheme)
    }

    /// As `Signature::verify_aggregated`, using the session's
    /// hash-to-G2 cache when all messages are 32 bytes.
    pub fn verify_aggregated(
      &self,
      sig: &Signature,
      msgs: &MessageVec,
      pks: &PublicKeyVec,
      scheme: Scheme,
    ) -> Result<(), PkcError> {
      if msgs.0.iter().all(|m| m.len() == 32) {
        match scheme {
          Scheme::Legacy => {
            let mut points = Vec::with_capacity(msgs.0.len());
            for msg in &msgs.0 {
              let msg32: &[u8; 32] = msg.as_slice().try_into().map_err(|_| PkcError::InvalidLength)?;
              points.push(self.0.msg_point_legacy(msg32)?);
            }
            let point_refs: Vec<_> = points.iter().collect();
            let owned = pks_to_legacy(&pks.0)?;
            let refs: Vec<&ChiaPk> = owned.iter().map(|c| &**c).collect();
            return Ok(sig.0.as_legacy()?.verify_aggregates_prehashed(&point_refs, &refs)?);
          }
          Scheme::Basic => {
            let mut points = Vec::with_capacity(msgs.0.len());
            for msg in &msgs.0 {
              let msg32: &[u8; 32] = msg.as_slice().try_into().map_err(|_| PkcError::InvalidLength)?;
              points.push(self.0.msg_point_basic(msg32)?);
            }
            let point_refs: Vec<_> = points.iter().collect();
            let owned = pks_to_basic(&pks.0)?;
            let refs: Vec<&IetfPk> = owned.iter().map(|c| &**c).collect();
            return Ok(sig.0.as_basic()?.verify_aggregates_prehashed(&point_refs, &refs)?);
          }
        }
      }
      sig.verify_aggregated(msgs, pks, scheme)
    }

    /// As `Signature::verify_secure`; cache-accelerated variants
    /// are introduced per technique.
    pub fn verify_secure(
      &self,
      sig: &Signature,
      pks: &PublicKeyVec,
      msg: &[u8],
      scheme: Scheme,
    ) -> Result<(), PkcError> {
      sig.verify_secure(pks, msg, scheme)
    }

    /// As `Signature::aggregate_secure`.
    pub fn aggregate_secure(
      &self,
      sigs: &SignatureVec,
      pks: &PublicKeyVec,
      scheme: Scheme,
    ) -> Result<Box<Signature>, PkcError> {
      Signature::aggregate_secure(sigs, pks, scheme)
    }

    /// As `PublicKey::from_bytes`.
    pub fn parse_public_key(&self, bytes: &[u8], scheme: Scheme) -> Result<Box<PublicKey>, PkcError> {
      PublicKey::from_bytes(bytes, scheme)
    }

    /// As `Signature::from_bytes`.
    pub fn parse_signature(&self, bytes: &[u8], scheme: Scheme) -> Result<Box<Signature>, PkcError> {
      Signature::from_bytes(bytes, scheme)
    }

    /// As `PublicKey::derive_share`.
    pub fn public_key_share(
      &self,
      masters: &PublicKeyVec,
      id: &[u8],
      scheme: Scheme,
    ) -> Result<Box<PublicKey>, PkcError> {
      PublicKey::derive_share(masters, id, scheme)
    }

    /// As `Signature::recover`.
    pub fn recover_signature(
      &self,
      sigs: &SignatureVec,
      ids: &IdVec,
      scheme: Scheme,
    ) -> Result<Box<Signature>, PkcError> {
      Signature::recover(sigs, ids, scheme)
    }
  }
}
