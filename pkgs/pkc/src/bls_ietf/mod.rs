//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! IETF BLS12-381 signatures (basic scheme, min-pubkey-size).

pub use crate::bls::BlsError;
pub type SecretKey = crate::bls::BlsSecretKey<crate::bls::BlsScIetf>;
pub type PublicKey = crate::bls::BlsPublicKey<crate::bls::BlsScIetf>;
pub type Signature = crate::bls::BlsSignature<crate::bls::BlsScIetf>;
