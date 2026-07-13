//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! IETF BLS12-381 signatures (basic scheme, min-pubkey-size).

mod agg;

pub mod threshold;

pub use crate::bls::BlsError;
pub use agg::{
  aggregate_pk, aggregate_sig, aggregate_sk, fast_verify_aggregates, secure_verify_aggregates, verify_aggregates,
};
pub type SecretKey = crate::bls::BlsSecretKey<crate::bls::BlsScIetf>;
pub type PublicKey = crate::bls::BlsPublicKey<crate::bls::BlsScIetf>;
pub type Signature = crate::bls::BlsSignature<crate::bls::BlsScIetf>;
