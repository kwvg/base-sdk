//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! BLS primitives shared between bls_ietf and bls_chia.

pub(crate) mod contract;
pub(crate) mod threshold;

use crate::prelude::*;

use dash_num::Hash256;

/// Sum secret key scalars (mod group order) via blst FFI.
#[expect(unsafe_code, reason = "blst C FFI")]
pub(crate) fn sum_sk_scalars(key_bytes: &[[u8; 32]]) -> Result<[u8; 32], ()> {
  use blst::*;
  use zeroize::Zeroize;
  let mut acc = blst_fr::default();
  for bytes in key_bytes {
    let mut scalar = blst_scalar::default();
    unsafe { blst_scalar_from_bendian(&mut scalar, bytes.as_ptr()) };
    let mut fr = blst_fr::default();
    unsafe { blst_fr_from_scalar(&mut fr, &scalar) };
    let mut tmp = blst_fr::default();
    unsafe { blst_fr_add(&mut tmp, &acc, &fr) };
    acc = tmp;
  }
  let mut out_scalar = blst_scalar::default();
  unsafe { blst_scalar_from_fr(&mut out_scalar, &acc) };
  let mut out_bytes = [0u8; 32];
  unsafe { blst_bendian_from_scalar(out_bytes.as_mut_ptr(), &out_scalar) };
  acc.l.zeroize();
  out_scalar.b.zeroize();
  Ok(out_bytes)
}

/// Generate secret key shares from a polynomial with the
/// given constant term. Returns a Vec of (id, share_bytes)
/// pairs.
#[expect(unsafe_code, reason = "blst C FFI")]
pub(crate) fn generate_shares(
  sk_bytes: &[u8; 32],
  threshold: usize,
  ids: &[Hash256],
  rng: &mut impl rand_core::CryptoRngCore,
) -> Result<Vec<(Hash256, [u8; 32])>, ()> {
  use blst::*;
  use zeroize::Zeroize;

  let mut coeffs = Vec::with_capacity(threshold);

  let mut sk_fr = blst_fr::default();
  let mut sk_scalar = blst_scalar::default();
  unsafe { blst_scalar_from_bendian(&mut sk_scalar, sk_bytes.as_ptr()) };
  unsafe { blst_fr_from_scalar(&mut sk_fr, &sk_scalar) };
  coeffs.push(sk_fr);

  for _ in 1..threshold {
    // Generate random 32-byte IKM from CSPRNG
    let mut ikm = zeroize::Zeroizing::new([0u8; 32]);
    rng.fill_bytes(&mut *ikm);
    let rand_sk = blst::min_pk::SecretKey::key_gen(ikm.as_ref(), &[]).map_err(|_| ())?;
    let mut rand_bytes = rand_sk.to_bytes();
    let mut rand_scalar = blst_scalar::default();
    unsafe { blst_scalar_from_bendian(&mut rand_scalar, rand_bytes.as_ptr()) };
    let mut rand_fr = blst_fr::default();
    unsafe { blst_fr_from_scalar(&mut rand_fr, &rand_scalar) };
    coeffs.push(rand_fr);
    rand_bytes.zeroize();
  }

  let mut shares = Vec::with_capacity(ids.len());
  for id in ids {
    let x = threshold::fr_from_hash(id);
    let y = threshold::poly_eval(&coeffs, &x);

    let mut y_scalar = blst_scalar::default();
    unsafe { blst_scalar_from_fr(&mut y_scalar, &y) };
    let mut y_bytes = [0u8; 32];
    unsafe { blst_bendian_from_scalar(y_bytes.as_mut_ptr(), &y_scalar) };
    y_scalar.b.zeroize();

    shares.push((*id, y_bytes));
  }

  // Zeroize secret polynomial coefficients.
  for coeff in &mut coeffs {
    coeff.l.zeroize();
  }
  sk_scalar.b.zeroize();
  sk_fr.l.zeroize();

  Ok(shares)
}

/// Implement Hash via to_bytes() for a BLS type.
macro_rules! impl_hash_via_bytes {
  ($ty:ty) => {
    impl core::hash::Hash for $ty {
      fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        self.to_bytes().hash(state);
      }
    }
  };
}
pub(crate) use impl_hash_via_bytes;
