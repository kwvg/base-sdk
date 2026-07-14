//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! BLS-IES encryption and decryption operations.

use super::error::BlsError;
use super::ies_bytes::{BlsIesBytes, BlsIesMultiBytes, BLS_IES_IV_LEN};
use super::public_ops::BlsPublicKey;
use super::secret_ops::BlsSecretKey;
use super::BlsScIetf;
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
/// serialization of the shared public key.
fn derive_aes_key(shared: &BlsPublicKey<BlsScIetf>) -> Zeroizing<[u8; 32]> {
  let bytes = Zeroizing::new(shared.to_bytes());
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

impl BlsPublicKey<BlsScIetf> {
  /// Encrypt a single blob for this recipient.
  ///
  /// The blob decrypts at recipient index 0.
  ///
  /// # Errors
  ///
  /// Returns `InvalidPlaintextLength` if `plaintext.len()` is
  /// not a multiple of 16.
  pub fn ies_encrypt(&self, plaintext: &[u8], rng: &mut impl RngCore) -> Result<BlsIesBytes, BlsError> {
    if plaintext.len() % AES_BLOCK_LEN != 0 {
      return Err(BlsError::InvalidPlaintextLength);
    }

    let mut ikm = Zeroizing::new([0u8; 32]);
    rng.fill_bytes(ikm.as_mut());
    let eph_sk = BlsSecretKey::<BlsScIetf>::generate(ikm.as_ref())?;
    let eph_pk = eph_sk.public_key();

    let shared = BlsPublicKey::dh_exchange(&eph_sk, self)?;
    let aes_key = derive_aes_key(&shared);

    let mut iv_seed = [0u8; BLS_IES_IV_LEN];
    rng.fill_bytes(&mut iv_seed);

    let ciphertext = aes_cbc_encrypt(&aes_key, &iv_seed, plaintext);

    Ok(BlsIesBytes::new(eph_pk.to_bytes(), iv_seed, ciphertext))
  }

  /// Encrypt the same plaintext for multiple recipients.
  ///
  /// Each recipient's blob is encrypted under the IV at its
  /// index in the SHA256d chain of the shared seed.
  ///
  /// # Errors
  ///
  /// Returns `InvalidPlaintextLength` if `plaintext.len()` is
  /// not a multiple of 16.
  pub fn ies_encrypt_multi(
    recipients: &[&Self],
    plaintext: &[u8],
    rng: &mut impl RngCore,
  ) -> Result<BlsIesMultiBytes, BlsError> {
    if plaintext.len() % AES_BLOCK_LEN != 0 {
      return Err(BlsError::InvalidPlaintextLength);
    }

    let mut ikm = Zeroizing::new([0u8; 32]);
    rng.fill_bytes(ikm.as_mut());
    let eph_sk = BlsSecretKey::<BlsScIetf>::generate(ikm.as_ref())?;
    let eph_pk = eph_sk.public_key();

    let mut iv_seed = [0u8; BLS_IES_IV_LEN];
    rng.fill_bytes(&mut iv_seed);

    let mut iv = iv_seed;
    let mut blobs = Vec::with_capacity(recipients.len());
    for &rpk in recipients {
      let shared = BlsPublicKey::dh_exchange(&eph_sk, rpk)?;
      let aes_key = derive_aes_key(&shared);
      let ct = aes_cbc_encrypt(&aes_key, &iv, plaintext);
      blobs.push(ct);
      iv = sha256d(&iv);
    }

    Ok(BlsIesMultiBytes::new(eph_pk.to_bytes(), iv_seed, blobs))
  }
}

impl BlsSecretKey<BlsScIetf> {
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

    let eph_pk = BlsPublicKey::<BlsScIetf>::from_bytes(blob.ephemeral_pk())?;
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

    let eph_pk = BlsPublicKey::<BlsScIetf>::from_bytes(multi.ephemeral_pk())?;
    let shared = BlsPublicKey::dh_exchange(self, &eph_pk)?;
    let aes_key = derive_aes_key(&shared);
    let iv = iv_at_index(multi.iv_seed(), recipient_index);

    Ok(aes_cbc_decrypt(&aes_key, &iv, ct))
  }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "test code")]
mod tests {
  use crate::bls::{BlsIesBytes, BlsPublicKey, BlsScIetf, BlsSecretKey};

  use rstest::*;

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

    let multi = BlsPublicKey::ies_encrypt_multi(&pk_refs, &plaintext, &mut rng).unwrap();

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

    let multi = BlsPublicKey::ies_encrypt_multi(&pk_refs, &plaintext, &mut rng).unwrap();

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
    let multi = BlsPublicKey::ies_encrypt_multi(&pk_refs, &plaintext, &mut rng).unwrap();
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

    let multi = BlsPublicKey::ies_encrypt_multi(&[&pk], &plaintext, &mut rng).unwrap();
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
