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

/// Derives the AES-256 key from a DH shared point.
fn derive_aes_key(shared: &BlsPublicKey<BlsScIetf>) -> [u8; 32] {
  let bytes = shared.to_bytes();
  let mut key = [0u8; 32];
  key.copy_from_slice(&bytes[..32]);
  key
}

/// Computes SHA256d(input) = SHA256(SHA256(input)).
fn sha256d(input: &[u8]) -> [u8; 32] {
  let first = Sha256::digest(input);
  let second = Sha256::digest(first);
  second.into()
}

/// Encrypts plaintext using AES-256-CBC with chained IVs.
fn aes_cbc_encrypt(key: &[u8; 32], iv_seed: &[u8; BLS_IES_IV_LEN], plaintext: &[u8]) -> Vec<u8> {
  let cipher = Aes256::new(key.into());
  let num_blocks = plaintext.len() / 16;
  let mut output = vec![0u8; plaintext.len()];
  let mut current_iv = *iv_seed;

  for i in 0..num_blocks {
    let block_start = i * 16;
    let block_end = block_start + 16;
    let mut block = aes::Block::default();
    for j in 0..16 {
      block[j] = plaintext[block_start + j] ^ current_iv[j];
    }
    cipher.encrypt_block(&mut block);
    output[block_start..block_end].copy_from_slice(&block);
    current_iv = sha256d(&current_iv);
  }

  output
}

/// Decrypts ciphertext using AES-256-CBC with chained IVs.
fn aes_cbc_decrypt(key: &[u8; 32], iv_seed: &[u8; BLS_IES_IV_LEN], ciphertext: &[u8]) -> Vec<u8> {
  let cipher = Aes256::new(key.into());
  let num_blocks = ciphertext.len() / 16;
  let mut output = vec![0u8; ciphertext.len()];
  let mut current_iv = *iv_seed;

  for i in 0..num_blocks {
    let block_start = i * 16;
    let block_end = block_start + 16;
    let mut block = aes::Block::default();
    block.copy_from_slice(&ciphertext[block_start..block_end]);
    cipher.decrypt_block(&mut block);
    for j in 0..16 {
      output[block_start + j] = block[j] ^ current_iv[j];
    }
    current_iv = sha256d(&current_iv);
  }

  output
}

impl BlsPublicKey<BlsScIetf> {
  /// Encrypt a single blob for this recipient.
  ///
  /// # Errors
  ///
  /// Returns `InvalidPlaintextLength` if `plaintext.len()` is
  /// not a multiple of 16.
  pub fn ies_encrypt(&self, plaintext: &[u8], rng: &mut impl RngCore) -> Result<BlsIesBytes, BlsError> {
    if plaintext.len() % 16 != 0 {
      return Err(BlsError::InvalidPlaintextLength);
    }

    let mut ikm = [0u8; 32];
    rng.fill_bytes(&mut ikm);
    let eph_sk = BlsSecretKey::<BlsScIetf>::generate(&ikm)?;
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
  /// # Errors
  ///
  /// Returns `InvalidPlaintextLength` if `plaintext.len()` is
  /// not a multiple of 16.
  pub fn ies_encrypt_multi(
    recipients: &[&Self],
    plaintext: &[u8],
    rng: &mut impl RngCore,
  ) -> Result<BlsIesMultiBytes, BlsError> {
    if plaintext.len() % 16 != 0 {
      return Err(BlsError::InvalidPlaintextLength);
    }

    let mut ikm = [0u8; 32];
    rng.fill_bytes(&mut ikm);
    let eph_sk = BlsSecretKey::<BlsScIetf>::generate(&ikm)?;
    let eph_pk = eph_sk.public_key();

    let mut iv_seed = [0u8; BLS_IES_IV_LEN];
    rng.fill_bytes(&mut iv_seed);

    let mut blobs = Vec::with_capacity(recipients.len());
    for &rpk in recipients {
      let shared = BlsPublicKey::dh_exchange(&eph_sk, rpk)?;
      let aes_key = derive_aes_key(&shared);
      let ct = aes_cbc_encrypt(&aes_key, &iv_seed, plaintext);
      blobs.push(ct);
    }

    Ok(BlsIesMultiBytes::new(eph_pk.to_bytes(), iv_seed, blobs))
  }
}

impl BlsSecretKey<BlsScIetf> {
  /// Decrypt a single BLS-IES blob.
  ///
  /// # Errors
  ///
  /// Returns `InvalidPublicKey` if the ephemeral key is invalid,
  /// or `DecryptionFailed` if the ciphertext length is not
  /// aligned.
  pub fn ies_decrypt(&self, blob: &BlsIesBytes) -> Result<Vec<u8>, BlsError> {
    if blob.data().len() % 16 != 0 {
      return Err(BlsError::DecryptionFailed);
    }

    let eph_pk = BlsPublicKey::<BlsScIetf>::from_bytes(blob.ephemeral_pk())?;
    let shared = BlsPublicKey::dh_exchange(self, &eph_pk)?;
    let aes_key = derive_aes_key(&shared);

    Ok(aes_cbc_decrypt(&aes_key, blob.iv_seed(), blob.data()))
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
    if ct.len() % 16 != 0 {
      return Err(BlsError::DecryptionFailed);
    }

    let eph_pk = BlsPublicKey::<BlsScIetf>::from_bytes(multi.ephemeral_pk())?;
    let shared = BlsPublicKey::dh_exchange(self, &eph_pk)?;
    let aes_key = derive_aes_key(&shared);

    Ok(aes_cbc_decrypt(&aes_key, multi.iv_seed(), ct))
  }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "test code")]
mod tests {
  use crate::bls::{BlsPublicKey, BlsScIetf, BlsSecretKey};

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
    let recovered = sk.ies_decrypt(&blob).unwrap();
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
    let decrypted = wrong_sk.ies_decrypt(&blob).unwrap();
    assert_ne!(decrypted.as_slice(), &plaintext);
  }

  #[rstest]
  fn empty_plaintext_roundtrip() {
    let sk = make_sk(40);
    let pk = sk.public_key();
    let plaintext: [u8; 0] = [];
    let mut rng = rand_core::OsRng;

    let blob = pk.ies_encrypt(&plaintext, &mut rng).unwrap();
    let recovered = sk.ies_decrypt(&blob).unwrap();
    assert!(recovered.is_empty());
  }
}
