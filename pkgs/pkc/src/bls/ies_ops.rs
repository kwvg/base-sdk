//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! BLS-IES encryption and decryption operations.

use super::error::BlsError;
use super::ies_bytes::{BlsIesBytes, BlsIesMultiBytes, BLS_IES_IV_LEN};
use super::public_ops::BlsPublicKey;
use super::scheme_ops::BlsScheme;
use super::secret_ops::BlsSecretKey;
use super::BlsSchemeId;
use crate::prelude::*;

use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit};
use aes::Aes256;
use rand_core::RngCore;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

/// AES-CBC block length in bytes.
const AES_BLOCK_LEN: usize = 16;

/// Derives the AES-256 key from a DH shared point.
///
/// Matches Dash Core: the first 32 bytes of the basic-scheme
/// serialization of the shared public key, regardless of which
/// scheme carries the ephemeral key (`ToByteVector(false)`).
fn derive_aes_key<S: BlsSchemeId + BlsScheme>(shared: &BlsPublicKey<S>) -> Zeroizing<[u8; 32]> {
  let bytes = Zeroizing::new(S::pk_to_ietf_bytes(&shared.0));
  let mut key = Zeroizing::new([0u8; 32]);
  key.copy_from_slice(&bytes[..32]);
  key
}

/// Computes SHA256d(input) = SHA256(SHA256(input)).
fn sha256d(input: &[u8]) -> [u8; 32] {
  let first = Sha256::digest(input);
  let second = Sha256::digest(first);
  second.into()
}

/// Derives the IV for a recipient index.
///
/// Matches Dash Core `CBLSIESEncryptedBlob::GetIV`: the seed is
/// advanced by SHA256d once per index; CBC uses its first 16 bytes.
fn iv_at_index(iv_seed: &[u8; BLS_IES_IV_LEN], index: usize) -> [u8; BLS_IES_IV_LEN] {
  let mut iv = *iv_seed;
  for _ in 0..index {
    iv = sha256d(&iv);
  }
  iv
}

/// Encrypts plaintext using unpadded AES-256-CBC.
fn aes_cbc_encrypt(key: &[u8; 32], iv: &[u8; BLS_IES_IV_LEN], plaintext: &[u8]) -> Vec<u8> {
  let cipher = Aes256::new(key.into());
  let num_blocks = plaintext.len() / AES_BLOCK_LEN;
  let mut output = vec![0u8; plaintext.len()];
  let mut chain = [0u8; AES_BLOCK_LEN];
  chain.copy_from_slice(&iv[..AES_BLOCK_LEN]);

  for i in 0..num_blocks {
    let block_start = i * AES_BLOCK_LEN;
    let block_end = block_start + AES_BLOCK_LEN;
    let mut block = aes::Block::default();
    for j in 0..AES_BLOCK_LEN {
      block[j] = plaintext[block_start + j] ^ chain[j];
    }
    cipher.encrypt_block(&mut block);
    output[block_start..block_end].copy_from_slice(&block);
    chain.copy_from_slice(&block);
  }

  output
}

/// Decrypts ciphertext using unpadded AES-256-CBC.
fn aes_cbc_decrypt(key: &[u8; 32], iv: &[u8; BLS_IES_IV_LEN], ciphertext: &[u8]) -> Vec<u8> {
  let cipher = Aes256::new(key.into());
  let num_blocks = ciphertext.len() / AES_BLOCK_LEN;
  let mut output = vec![0u8; ciphertext.len()];
  let mut chain = [0u8; AES_BLOCK_LEN];
  chain.copy_from_slice(&iv[..AES_BLOCK_LEN]);

  for i in 0..num_blocks {
    let block_start = i * AES_BLOCK_LEN;
    let block_end = block_start + AES_BLOCK_LEN;
    let mut block = aes::Block::default();
    block.copy_from_slice(&ciphertext[block_start..block_end]);
    cipher.decrypt_block(&mut block);
    for j in 0..AES_BLOCK_LEN {
      output[block_start + j] = block[j] ^ chain[j];
    }
    chain.copy_from_slice(&ciphertext[block_start..block_end]);
  }

  output
}

impl<S: BlsSchemeId + BlsScheme> BlsPublicKey<S> {
  /// Encrypt a single blob for this recipient.
  ///
  /// The blob decrypts at recipient index 0.
  ///
  /// # Errors
  ///
  /// Returns `InvalidPlaintextLength` if `plaintext.len()` is
  /// not a multiple of 16.
  pub fn ies_encrypt(&self, plaintext: &[u8], rng: &mut impl RngCore) -> Result<BlsIesBytes, BlsError> {
    let (eph_sk, iv_seed) = ies_ephemeral::<S>(rng)?;
    self.ies_encrypt_with(&eph_sk, &iv_seed, plaintext)
  }

  /// Deterministic single-recipient encryption core.
  pub(crate) fn ies_encrypt_with(
    &self,
    eph_sk: &BlsSecretKey<S>,
    iv_seed: &[u8; BLS_IES_IV_LEN],
    plaintext: &[u8],
  ) -> Result<BlsIesBytes, BlsError> {
    if plaintext.len() % AES_BLOCK_LEN != 0 {
      return Err(BlsError::InvalidPlaintextLength);
    }

    let eph_pk = eph_sk.public_key();
    let shared = BlsPublicKey::dh_exchange(eph_sk, self)?;
    let aes_key = derive_aes_key(&shared);
    let ciphertext = aes_cbc_encrypt(&aes_key, iv_seed, plaintext);

    Ok(BlsIesBytes::new(eph_pk.to_bytes(), *iv_seed, ciphertext))
  }

  /// Encrypt one plaintext per recipient under a shared
  /// ephemeral key.
  ///
  /// Mirrors Dash Core `CBLSIESMultiRecipientBlobs`: recipient
  /// `i`'s blob is encrypted under the IV at index `i` in the
  /// SHA256d chain of the shared seed. Each recipient may get a
  /// different plaintext (in the DKG each member receives its
  /// own secret key share).
  ///
  /// # Errors
  ///
  /// Returns `CountMismatch` if `plaintexts.len()` differs from
  /// `recipients.len()`, or `InvalidPlaintextLength` if any
  /// plaintext is not a multiple of 16 bytes.
  pub fn ies_encrypt_multi(
    recipients: &[&Self],
    plaintexts: &[&[u8]],
    rng: &mut impl RngCore,
  ) -> Result<BlsIesMultiBytes, BlsError> {
    let (eph_sk, iv_seed) = ies_ephemeral::<S>(rng)?;
    Self::ies_encrypt_multi_with(&eph_sk, &iv_seed, recipients, plaintexts)
  }

  /// Deterministic multi-recipient encryption core.
  pub(crate) fn ies_encrypt_multi_with(
    eph_sk: &BlsSecretKey<S>,
    iv_seed: &[u8; BLS_IES_IV_LEN],
    recipients: &[&Self],
    plaintexts: &[&[u8]],
  ) -> Result<BlsIesMultiBytes, BlsError> {
    if plaintexts.len() != recipients.len() {
      return Err(BlsError::CountMismatch);
    }
    if plaintexts.iter().any(|p| p.len() % AES_BLOCK_LEN != 0) {
      return Err(BlsError::InvalidPlaintextLength);
    }

    let eph_pk = eph_sk.public_key();
    let mut iv = *iv_seed;
    let mut blobs = Vec::with_capacity(recipients.len());
    for (&rpk, plaintext) in recipients.iter().zip(plaintexts) {
      let shared = BlsPublicKey::dh_exchange(eph_sk, rpk)?;
      let aes_key = derive_aes_key(&shared);
      let ct = aes_cbc_encrypt(&aes_key, &iv, plaintext);
      blobs.push(ct);
      iv = sha256d(&iv);
    }

    Ok(BlsIesMultiBytes::new(eph_pk.to_bytes(), *iv_seed, blobs))
  }
}

/// Generates a fresh ephemeral secret key and IV seed.
fn ies_ephemeral<S: BlsSchemeId + BlsScheme>(
  rng: &mut impl RngCore,
) -> Result<(BlsSecretKey<S>, [u8; BLS_IES_IV_LEN]), BlsError> {
  let mut ikm = Zeroizing::new([0u8; 32]);
  rng.fill_bytes(ikm.as_mut());
  let eph_sk = BlsSecretKey::<S>::generate(ikm.as_ref())?;

  let mut iv_seed = [0u8; BLS_IES_IV_LEN];
  rng.fill_bytes(&mut iv_seed);
  Ok((eph_sk, iv_seed))
}

impl<S: BlsSchemeId + BlsScheme> BlsSecretKey<S> {
  /// Decrypt a single BLS-IES blob.
  ///
  /// `recipient_index` selects the IV in the SHA256d chain; use 0
  /// for standalone blobs, or the original recipient index for a
  /// blob extracted from a multi-recipient message.
  ///
  /// # Errors
  ///
  /// Returns `InvalidPublicKey` if the ephemeral key is invalid,
  /// or `DecryptionFailed` if the ciphertext length is not
  /// aligned.
  pub fn ies_decrypt(&self, blob: &BlsIesBytes, recipient_index: usize) -> Result<Vec<u8>, BlsError> {
    if blob.data().len() % AES_BLOCK_LEN != 0 {
      return Err(BlsError::DecryptionFailed);
    }

    let eph_pk = BlsPublicKey::<S>::from_bytes(blob.ephemeral_pk())?;
    let shared = BlsPublicKey::dh_exchange(self, &eph_pk)?;
    let aes_key = derive_aes_key(&shared);
    let iv = iv_at_index(blob.iv_seed(), recipient_index);

    Ok(aes_cbc_decrypt(&aes_key, &iv, blob.data()))
  }

  /// Decrypt one recipient's blob from a multi-recipient
  /// message.
  ///
  /// # Errors
  ///
  /// Returns `IndexOutOfRange` if
  /// `recipient_index >= multi.blobs().len()`.
  pub fn ies_decrypt_multi(&self, multi: &BlsIesMultiBytes, recipient_index: usize) -> Result<Vec<u8>, BlsError> {
    let blobs = multi.blobs();
    if recipient_index >= blobs.len() {
      return Err(BlsError::IndexOutOfRange);
    }
    let ct = &blobs[recipient_index];
    if ct.len() % AES_BLOCK_LEN != 0 {
      return Err(BlsError::DecryptionFailed);
    }

    let eph_pk = BlsPublicKey::<S>::from_bytes(multi.ephemeral_pk())?;
    let shared = BlsPublicKey::dh_exchange(self, &eph_pk)?;
    let aes_key = derive_aes_key(&shared);
    let iv = iv_at_index(multi.iv_seed(), recipient_index);

    Ok(aes_cbc_decrypt(&aes_key, &iv, ct))
  }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "test code")]
mod tests {
  use crate::bls::scheme_ops::BlsScheme;
  use crate::bls::{BlsIesBytes, BlsIesMultiBytes, BlsPublicKey, BlsScChia, BlsScIetf, BlsSchemeId, BlsSecretKey};
  use crate::tests::{hex_to_32, hex_to_48};

  use dash_dev::load_corpus_json;
  use hex_conservative::FromHex;
  use rstest::*;

  struct IesKat {
    eph_sk: [u8; 32],
    eph_pk: [u8; 48],
    iv_seed: [u8; 32],
    recipient_sks: alloc::vec::Vec<[u8; 32]>,
    recipient_pks: alloc::vec::Vec<[u8; 48]>,
    plaintexts: alloc::vec::Vec<alloc::vec::Vec<u8>>,
    ciphertexts: alloc::vec::Vec<alloc::vec::Vec<u8>>,
  }

  /// Loads the Dash Core derived vectors, picking the ephemeral
  /// and recipient pk serialization for the scheme mode.
  fn load_ies_kat(pk_field: &str) -> IesKat {
    let f = load_corpus_json(env!("CARGO_MANIFEST_DIR"), "bls_ies");
    let kat = &f["ies"];
    let recipients = kat["recipients"].as_array().unwrap();
    IesKat {
      eph_sk: hex_to_32(kat["eph_sk"].as_str().unwrap()),
      eph_pk: hex_to_48(
        kat[if pk_field == "pk_legacy" {
          "eph_pk_legacy"
        } else {
          "eph_pk_basic"
        }]
        .as_str()
        .unwrap(),
      ),
      iv_seed: hex_to_32(kat["iv_seed"].as_str().unwrap()),
      recipient_sks: recipients
        .iter()
        .map(|r| hex_to_32(r["sk"].as_str().unwrap()))
        .collect(),
      recipient_pks: recipients
        .iter()
        .map(|r| hex_to_48(r[pk_field].as_str().unwrap()))
        .collect(),
      plaintexts: recipients
        .iter()
        .map(|r| alloc::vec::Vec::from_hex(r["plaintext"].as_str().unwrap()).unwrap())
        .collect(),
      ciphertexts: recipients
        .iter()
        .map(|r| alloc::vec::Vec::from_hex(r["ciphertext"].as_str().unwrap()).unwrap())
        .collect(),
    }
  }

  fn assert_kat_decrypt<S: BlsSchemeId + BlsScheme>(pk_field: &str) {
    // Vectors derived from Dash Core: libdashbls DH + Dash's
    // AES256CBCEncrypt reproducing CBLSIESMultiRecipientBlobs.
    let kat = load_ies_kat(pk_field);

    let multi = BlsIesMultiBytes::new(kat.eph_pk, kat.iv_seed, kat.ciphertexts.clone());
    for (i, sk_bytes) in kat.recipient_sks.iter().enumerate() {
      let sk = BlsSecretKey::<S>::from_bytes(sk_bytes).unwrap();
      assert_eq!(sk.ies_decrypt_multi(&multi, i).unwrap(), kat.plaintexts[i]);

      // Extracted single blob (Dash Core `Get(idx)` semantics).
      let blob = BlsIesBytes::new(kat.eph_pk, kat.iv_seed, kat.ciphertexts[i].clone());
      assert_eq!(sk.ies_decrypt(&blob, i).unwrap(), kat.plaintexts[i]);
    }
  }

  #[rstest]
  #[case::chia(assert_kat_decrypt::<BlsScChia>, "pk_legacy")]
  #[case::ietf(assert_kat_decrypt::<BlsScIetf>, "pk_basic")]
  fn kat_decrypt_matches_dashbls(#[case] assertion: fn(&str), #[case] pk_field: &str) {
    assertion(pk_field);
  }

  fn assert_kat_encrypt<S: BlsSchemeId + BlsScheme>(pk_field: &str) {
    let kat = load_ies_kat(pk_field);
    let eph_sk = BlsSecretKey::<S>::from_bytes(&kat.eph_sk).unwrap();
    let pks: alloc::vec::Vec<BlsPublicKey<S>> = kat
      .recipient_pks
      .iter()
      .map(|b| BlsPublicKey::from_bytes(b).unwrap())
      .collect();
    let pk_refs: alloc::vec::Vec<&BlsPublicKey<S>> = pks.iter().collect();
    let pts: alloc::vec::Vec<&[u8]> = kat.plaintexts.iter().map(|p| p.as_slice()).collect();

    let multi = BlsPublicKey::ies_encrypt_multi_with(&eph_sk, &kat.iv_seed, &pk_refs, &pts).unwrap();
    assert_eq!(*multi.ephemeral_pk(), kat.eph_pk);
    assert_eq!(multi.blobs(), kat.ciphertexts.as_slice());

    // Single-recipient core equals the first multi entry.
    let blob = pks[0]
      .ies_encrypt_with(&eph_sk, &kat.iv_seed, &kat.plaintexts[0])
      .unwrap();
    assert_eq!(blob.data(), kat.ciphertexts[0].as_slice());
  }

  #[rstest]
  #[case::chia(assert_kat_encrypt::<BlsScChia>, "pk_legacy")]
  #[case::ietf(assert_kat_encrypt::<BlsScIetf>, "pk_basic")]
  fn kat_encrypt_matches_dashbls(#[case] assertion: fn(&str), #[case] pk_field: &str) {
    assertion(pk_field);
  }

  fn make_sk(seed: u8) -> BlsSecretKey<BlsScIetf> {
    BlsSecretKey::generate(&[seed; 32]).unwrap()
  }

  #[rstest]
  fn encrypt_decrypt_roundtrip() {
    let sk = make_sk(1);
    let pk = sk.public_key();
    let plaintext = [0x42u8; 32];
    let mut rng = rand_core::OsRng;

    let blob = pk.ies_encrypt(&plaintext, &mut rng).unwrap();
    let recovered = sk.ies_decrypt(&blob, 0).unwrap();
    assert_eq!(recovered.as_slice(), &plaintext);
  }

  #[rstest]
  fn rejects_non_aligned_plaintext() {
    let sk = make_sk(2);
    let pk = sk.public_key();
    let plaintext = [0xffu8; 17];
    let mut rng = rand_core::OsRng;
    assert_eq!(
      pk.ies_encrypt(&plaintext, &mut rng).unwrap_err(),
      crate::bls::BlsError::InvalidPlaintextLength
    );
  }

  #[rstest]
  fn multi_encrypt_decrypt_roundtrip() {
    let sk1 = make_sk(10);
    let sk2 = make_sk(11);
    let sk3 = make_sk(12);
    let pks = [sk1.public_key(), sk2.public_key(), sk3.public_key()];
    let pk_refs: alloc::vec::Vec<&BlsPublicKey<BlsScIetf>> = pks.iter().collect();
    let plaintext = [0xabu8; 48];
    let mut rng = rand_core::OsRng;

    let pts: alloc::vec::Vec<&[u8]> = alloc::vec![&plaintext; 3];
    let multi = BlsPublicKey::ies_encrypt_multi(&pk_refs, &pts, &mut rng).unwrap();

    for (i, sk) in [&sk1, &sk2, &sk3].iter().enumerate() {
      let recovered = sk.ies_decrypt_multi(&multi, i).unwrap();
      assert_eq!(recovered.as_slice(), &plaintext);
    }
  }

  #[rstest]
  fn multi_blob_extracts_to_single() {
    let sk1 = make_sk(13);
    let sk2 = make_sk(14);
    let pks = [sk1.public_key(), sk2.public_key()];
    let pk_refs: alloc::vec::Vec<&BlsPublicKey<BlsScIetf>> = pks.iter().collect();
    let plaintext = [0x5au8; 32];
    let mut rng = rand_core::OsRng;

    let pts: alloc::vec::Vec<&[u8]> = alloc::vec![&plaintext; 2];
    let multi = BlsPublicKey::ies_encrypt_multi(&pk_refs, &pts, &mut rng).unwrap();

    // Mirrors Dash Core `CBLSIESMultiRecipientObjects::Get(idx)`:
    // an extracted blob keeps the shared seed and decrypts at its
    // original recipient index.
    let extracted = BlsIesBytes::new(*multi.ephemeral_pk(), *multi.iv_seed(), multi.blobs()[1].clone());
    let recovered = sk2.ies_decrypt(&extracted, 1).unwrap();
    assert_eq!(recovered.as_slice(), &plaintext);
    assert_ne!(sk2.ies_decrypt(&extracted, 0).unwrap().as_slice(), &plaintext);
  }

  #[rstest]
  fn multi_recipient_ciphertexts_differ_by_iv() {
    let sk = make_sk(15);
    let pk = sk.public_key();
    let pk_refs = [&pk, &pk];
    let plaintext = [0x77u8; 16];
    let mut rng = rand_core::OsRng;

    // Same recipient twice: same key, different chained IV.
    let multi = BlsPublicKey::ies_encrypt_multi(&pk_refs, &[&plaintext, &plaintext], &mut rng).unwrap();
    assert_ne!(multi.blobs()[0], multi.blobs()[1]);
  }

  #[rstest]
  fn cbc_chains_ciphertext_blocks() {
    let sk = make_sk(16);
    let pk = sk.public_key();
    // Two identical plaintext blocks must not produce identical
    // ciphertext blocks under CBC.
    let plaintext = [0x11u8; 32];
    let mut rng = rand_core::OsRng;

    let blob = pk.ies_encrypt(&plaintext, &mut rng).unwrap();
    assert_ne!(blob.data()[..16], blob.data()[16..32]);
  }

  #[rstest]
  fn multi_index_out_of_range() {
    let sk = make_sk(20);
    let pk = sk.public_key();
    let plaintext = [0u8; 16];
    let mut rng = rand_core::OsRng;

    let multi = BlsPublicKey::ies_encrypt_multi(&[&pk], &[&plaintext], &mut rng).unwrap();
    assert_eq!(
      sk.ies_decrypt_multi(&multi, 1).unwrap_err(),
      crate::bls::BlsError::IndexOutOfRange
    );
  }

  #[rstest]
  fn wrong_key_produces_different_plaintext() {
    let sk = make_sk(30);
    let pk = sk.public_key();
    let wrong_sk = make_sk(31);
    let plaintext = [0xddu8; 32];
    let mut rng = rand_core::OsRng;

    let blob = pk.ies_encrypt(&plaintext, &mut rng).unwrap();
    let decrypted = wrong_sk.ies_decrypt(&blob, 0).unwrap();
    assert_ne!(decrypted.as_slice(), &plaintext);
  }

  #[rstest]
  fn empty_plaintext_roundtrip() {
    let sk = make_sk(40);
    let pk = sk.public_key();
    let plaintext: [u8; 0] = [];
    let mut rng = rand_core::OsRng;

    let blob = pk.ies_encrypt(&plaintext, &mut rng).unwrap();
    let recovered = sk.ies_decrypt(&blob, 0).unwrap();
    assert!(recovered.is_empty());
  }
}
