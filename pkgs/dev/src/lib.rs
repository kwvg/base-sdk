//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Development and test utilities.

#![no_std]
#![expect(clippy::panic, clippy::unwrap_used, reason = "development crate")]

extern crate alloc;

mod corpus;
mod lambda;
mod prelude;

pub use corpus::CorpusEntry;
pub use lambda::{check_sptx, check_tx, check_wire};

cfg_if::cfg_if! {
  if #[cfg(feature = "std")] {
    extern crate std;

    pub use corpus::{load_corpus_file, load_corpus_json};
    #[cfg(feature = "serde")]
    pub use corpus::{assert_serde_rt, corpus_vectors, read_corpus, write_corpus};
    #[cfg(feature = "serde")]
    pub use corpus::bls::{
      bls_aggregate_pk, bls_aggregate_sig, bls_aggregate_sk, bls_dh, bls_hash, bls_keygen, bls_pk_serialization,
      bls_secure_aggregate, bls_sig_serialization, bls_sign, BlsPkAggEntry, BlsSigAggEntry,
      BlsSkAggEntry, BlsDhEntry, BlsHashEntry, BlsKeygenEntry, BlsPkSerEntry, BlsSecureAggEntry,
      BlsSigSerEntry, BlsSignEntry,
    };
    #[cfg(feature = "serde")]
    pub use corpus::ecdsa::{ecdsa_keygen, ecdsa_recover, ecdsa_sign, EcdsaKeygenEntry, EcdsaRecoverEntry, EcdsaSignEntry};
  }
}
