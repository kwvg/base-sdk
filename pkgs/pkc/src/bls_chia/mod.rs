//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Legacy BLS signatures (non-standard hash-to-G2, min-pubkey-size).

mod agg;

pub mod threshold;

pub use crate::bls::BlsError;
pub use agg::{aggregate_pk, aggregate_sig, aggregate_sk, fast_verify_aggregates};

pub type SecretKey = crate::bls::BlsSecretKey<crate::bls::BlsScChia>;
pub type PublicKey = crate::bls::BlsPublicKey<crate::bls::BlsScChia>;
pub type Signature = crate::bls::BlsSignature<crate::bls::BlsScChia>;
