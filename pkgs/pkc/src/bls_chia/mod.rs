//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Legacy BLS signatures (non-standard hash-to-G2, min-pubkey-size).

pub use crate::bls::BlsError;

pub type SecretKey = crate::bls::BlsSecretKey<crate::bls::BlsScChia>;
pub type PublicKey = crate::bls::BlsPublicKey<crate::bls::BlsScChia>;
pub type Signature = crate::bls::BlsSignature<crate::bls::BlsScChia>;
