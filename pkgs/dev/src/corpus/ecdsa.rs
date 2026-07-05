//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! ECDSA corpus vectors.

use crate::prelude::*;

use hex_conservative::FromHex;
use serde::Deserialize;

/// A keygen vector: secret key and expected compressed public key.
#[derive(Debug)]
pub struct EcdsaKeygenEntry {
  pub sk: [u8; 32],
  pub pk_compressed: [u8; 33],
}

/// A signing vector: secret key, message, expected signature, and recovery id.
#[derive(Debug)]
pub struct EcdsaSignEntry {
  pub sk: [u8; 32],
  pub msg: [u8; 32],
  pub sig: [u8; 64],
  pub recovery_id: u8,
}

/// A recovery vector: message, signature, recovery id, and expected public key.
#[derive(Debug)]
pub struct EcdsaRecoverEntry {
  pub msg: [u8; 32],
  pub sig: [u8; 64],
  pub recovery_id: u8,
  pub pk: [u8; 33],
}

pub fn ecdsa_keygen(corpus: &serde_json::Value, section: &str) -> Vec<EcdsaKeygenEntry> {
  #[derive(Deserialize)]
  struct Raw {
    sk: String,
    pk_compressed: String,
  }

  super::corpus_vectors::<Raw>(corpus, section)
    .into_iter()
    .map(|v| EcdsaKeygenEntry {
      sk: <[u8; 32]>::from_hex(&v.sk).unwrap(),
      pk_compressed: <[u8; 33]>::from_hex(&v.pk_compressed).unwrap(),
    })
    .collect()
}

pub fn ecdsa_sign(corpus: &serde_json::Value, section: &str) -> Vec<EcdsaSignEntry> {
  #[derive(Deserialize)]
  struct Raw {
    sk: String,
    msg: String,
    sig: String,
    recovery_id: u8,
  }

  super::corpus_vectors::<Raw>(corpus, section)
    .into_iter()
    .map(|v| EcdsaSignEntry {
      sk: <[u8; 32]>::from_hex(&v.sk).unwrap(),
      msg: <[u8; 32]>::from_hex(&v.msg).unwrap(),
      sig: <[u8; 64]>::from_hex(&v.sig).unwrap(),
      recovery_id: v.recovery_id,
    })
    .collect()
}

pub fn ecdsa_recover(corpus: &serde_json::Value, section: &str) -> Vec<EcdsaRecoverEntry> {
  #[derive(Deserialize)]
  struct Raw {
    msg: String,
    sig: String,
    recovery_id: u8,
    pk: String,
  }

  super::corpus_vectors::<Raw>(corpus, section)
    .into_iter()
    .map(|v| EcdsaRecoverEntry {
      msg: <[u8; 32]>::from_hex(&v.msg).unwrap(),
      sig: <[u8; 64]>::from_hex(&v.sig).unwrap(),
      recovery_id: v.recovery_id,
      pk: <[u8; 33]>::from_hex(&v.pk).unwrap(),
    })
    .collect()
}
