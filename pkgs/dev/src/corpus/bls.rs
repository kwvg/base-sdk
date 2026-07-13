//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! BLS corpus vectors.

use super::corpus_vectors;
use crate::prelude::*;

use hex_conservative::FromHex;
use serde::Deserialize;
use serde_json::Value;

#[derive(Debug)]
pub struct BlsHashEntry {
  pub msg: [u8; 32],
  pub t00_fp: [u8; 48],
  pub t01_fp: [u8; 48],
  pub t10_fp: [u8; 48],
  pub t11_fp: [u8; 48],
}

pub fn bls_hash(corpus: &Value, section: &str) -> Vec<BlsHashEntry> {
  #[derive(Deserialize)]
  struct Raw {
    msg: String,
    t00_fp: String,
    t01_fp: String,
    t10_fp: String,
    t11_fp: String,
  }

  corpus_vectors::<Raw>(corpus, section)
    .into_iter()
    .map(|v| BlsHashEntry {
      msg: <[u8; 32]>::from_hex(&v.msg).unwrap(),
      t00_fp: <[u8; 48]>::from_hex(&v.t00_fp).unwrap(),
      t01_fp: <[u8; 48]>::from_hex(&v.t01_fp).unwrap(),
      t10_fp: <[u8; 48]>::from_hex(&v.t10_fp).unwrap(),
      t11_fp: <[u8; 48]>::from_hex(&v.t11_fp).unwrap(),
    })
    .collect()
}

#[derive(Debug)]
pub struct BlsKeygenEntry {
  pub sk: [u8; 32],
  pub pk: [u8; 48],
}

pub fn bls_keygen(corpus: &Value, section: &str) -> Vec<BlsKeygenEntry> {
  #[derive(Deserialize)]
  struct Raw {
    sk: String,
    pk: String,
  }

  corpus_vectors::<Raw>(corpus, section)
    .into_iter()
    .map(|v| BlsKeygenEntry {
      sk: <[u8; 32]>::from_hex(&v.sk).unwrap(),
      pk: <[u8; 48]>::from_hex(&v.pk).unwrap(),
    })
    .collect()
}

#[derive(Debug)]
pub struct BlsDhEntry {
  pub sk: [u8; 32],
  pub peer_pk: [u8; 48],
  pub shared: [u8; 48],
}

pub fn bls_dh(corpus: &Value, section: &str) -> Vec<BlsDhEntry> {
  #[derive(Deserialize)]
  struct Raw {
    sk: String,
    peer_pk: String,
    shared: String,
  }

  corpus_vectors::<Raw>(corpus, section)
    .into_iter()
    .map(|v| BlsDhEntry {
      sk: <[u8; 32]>::from_hex(&v.sk).unwrap(),
      peer_pk: <[u8; 48]>::from_hex(&v.peer_pk).unwrap(),
      shared: <[u8; 48]>::from_hex(&v.shared).unwrap(),
    })
    .collect()
}

#[derive(Debug)]
pub struct BlsPkSerEntry {
  pub legacy: [u8; 48],
  pub ietf: [u8; 48],
}

pub fn bls_pk_serialization(corpus: &Value, section: &str) -> Vec<BlsPkSerEntry> {
  #[derive(Deserialize)]
  struct Raw {
    pk_legacy: String,
    pk_ietf: String,
  }

  corpus_vectors::<Raw>(corpus, section)
    .into_iter()
    .map(|v| BlsPkSerEntry {
      legacy: <[u8; 48]>::from_hex(&v.pk_legacy).unwrap(),
      ietf: <[u8; 48]>::from_hex(&v.pk_ietf).unwrap(),
    })
    .collect()
}

#[derive(Debug)]
pub struct BlsSigSerEntry {
  pub legacy: [u8; 96],
  pub ietf: [u8; 96],
}

pub fn bls_sig_serialization(corpus: &Value, section: &str) -> Vec<BlsSigSerEntry> {
  #[derive(Deserialize)]
  struct Raw {
    sig_legacy: String,
    sig_ietf: String,
  }

  corpus_vectors::<Raw>(corpus, section)
    .into_iter()
    .map(|v| BlsSigSerEntry {
      legacy: <[u8; 96]>::from_hex(&v.sig_legacy).unwrap(),
      ietf: <[u8; 96]>::from_hex(&v.sig_ietf).unwrap(),
    })
    .collect()
}

#[derive(Debug)]
pub struct BlsSignEntry {
  pub sk: [u8; 32],
  pub msg: [u8; 32],
  pub sig: [u8; 96],
}

pub fn bls_sign(corpus: &Value, section: &str) -> Vec<BlsSignEntry> {
  #[derive(Deserialize)]
  struct Raw {
    sk: String,
    msg: String,
    sig: String,
  }

  corpus_vectors::<Raw>(corpus, section)
    .into_iter()
    .map(|v| BlsSignEntry {
      sk: <[u8; 32]>::from_hex(&v.sk).unwrap(),
      msg: <[u8; 32]>::from_hex(&v.msg).unwrap(),
      sig: <[u8; 96]>::from_hex(&v.sig).unwrap(),
    })
    .collect()
}

#[derive(Debug)]
pub struct BlsPkAggEntry {
  pub pks: Vec<[u8; 48]>,
  pub aggregate: [u8; 48],
}

pub fn bls_aggregate_pk(corpus: &Value, section: &str) -> Vec<BlsPkAggEntry> {
  #[derive(Deserialize)]
  struct Raw {
    pks: Vec<String>,
    agg_pk: String,
  }

  corpus_vectors::<Raw>(corpus, section)
    .into_iter()
    .map(|v| BlsPkAggEntry {
      pks: v.pks.iter().map(|pk| <[u8; 48]>::from_hex(pk).unwrap()).collect(),
      aggregate: <[u8; 48]>::from_hex(&v.agg_pk).unwrap(),
    })
    .collect()
}

#[derive(Debug)]
pub struct BlsSigAggEntry {
  pub sigs: Vec<[u8; 96]>,
  pub aggregate: [u8; 96],
}

pub fn bls_aggregate_sig(corpus: &Value, section: &str) -> Vec<BlsSigAggEntry> {
  #[derive(Deserialize)]
  struct Raw {
    sigs: Vec<String>,
    agg_sig: String,
  }

  corpus_vectors::<Raw>(corpus, section)
    .into_iter()
    .map(|v| BlsSigAggEntry {
      sigs: v.sigs.iter().map(|sig| <[u8; 96]>::from_hex(sig).unwrap()).collect(),
      aggregate: <[u8; 96]>::from_hex(&v.agg_sig).unwrap(),
    })
    .collect()
}

#[derive(Debug)]
pub struct BlsSkAggEntry {
  pub sks: Vec<[u8; 32]>,
  pub aggregate: [u8; 32],
}

pub fn bls_aggregate_sk(corpus: &Value, section: &str) -> Vec<BlsSkAggEntry> {
  #[derive(Deserialize)]
  struct Raw {
    sks: Vec<String>,
    agg_sk: String,
  }

  corpus_vectors::<Raw>(corpus, section)
    .into_iter()
    .map(|v| BlsSkAggEntry {
      sks: v.sks.iter().map(|sk| <[u8; 32]>::from_hex(sk).unwrap()).collect(),
      aggregate: <[u8; 32]>::from_hex(&v.agg_sk).unwrap(),
    })
    .collect()
}

#[derive(Debug)]
pub struct BlsSecureAggEntry {
  pub msg: [u8; 32],
  pub pks: Vec<[u8; 48]>,
  pub sigs: Vec<[u8; 96]>,
  pub aggregate: [u8; 96],
}

pub fn bls_secure_aggregate(corpus: &Value, section: &str) -> Vec<BlsSecureAggEntry> {
  #[derive(Deserialize)]
  struct Raw {
    msg: String,
    pks: Vec<String>,
    sigs: Vec<String>,
    agg_sig_secure: String,
  }

  corpus_vectors::<Raw>(corpus, section)
    .into_iter()
    .map(|v| BlsSecureAggEntry {
      msg: <[u8; 32]>::from_hex(&v.msg).unwrap(),
      pks: v.pks.iter().map(|pk| <[u8; 48]>::from_hex(pk).unwrap()).collect(),
      sigs: v.sigs.iter().map(|sig| <[u8; 96]>::from_hex(sig).unwrap()).collect(),
      aggregate: <[u8; 96]>::from_hex(&v.agg_sig_secure).unwrap(),
    })
    .collect()
}
