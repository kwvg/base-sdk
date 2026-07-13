//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Legacy (Chia) BLS scheme: `BlsScheme` implementation.

use super::blst_ffi::{self, Fp, Fp2};
use super::chia_h2c;
use super::error::BlsError;
use super::scheme_ops::{self, BlsScheme};
use super::schemes::BlsScChia;

use blst::{blst_p1_affine, blst_p2_affine, blst_scalar};
use dash_num::Hash256;
use zeroize::Zeroize;

impl BlsScheme for BlsScChia {
  type InnerSk = blst_scalar;
  type InnerPk = blst_p1_affine;
  type InnerSig = blst_p2_affine;

  fn generate(ikm: &[u8]) -> Result<Self::InnerSk, BlsError> {
    let sk = blst::min_pk::SecretKey::key_gen(ikm, &[]).map_err(|_| BlsError::InvalidSecretKey)?;
    let bytes = sk.to_bytes();
    Self::sk_from_bytes(&bytes)
  }

  fn sk_from_bytes(b: &[u8; 32]) -> Result<Self::InnerSk, BlsError> {
    let scalar = blst_ffi::scalar_from_bendian(b);
    if blst_ffi::sk_check(&scalar) {
      Ok(scalar)
    } else {
      Err(BlsError::InvalidSecretKey)
    }
  }

  fn sk_to_bytes(sk: &Self::InnerSk) -> [u8; 32] {
    blst_ffi::bendian_from_scalar(sk)
  }

  fn derive_pk(sk: &Self::InnerSk) -> Self::InnerPk {
    blst_ffi::sk_to_pk2_in_g1(sk)
  }

  fn pk_from_bytes(b: &[u8; 48]) -> Result<Self::InnerPk, BlsError> {
    chia_deser_g1(b)
  }

  fn pk_to_bytes(pk: &Self::InnerPk) -> [u8; 48] {
    chia_ser_g1(pk)
  }

  fn sig_from_bytes(b: &[u8; 96]) -> Result<Self::InnerSig, BlsError> {
    chia_deser_g2(b)
  }

  fn sig_to_bytes(sig: &Self::InnerSig) -> [u8; 96] {
    chia_ser_g2(sig)
  }

  fn sign(sk: &Self::InnerSk, msg: &[u8]) -> Self::InnerSig {
    debug_assert!(blst_ffi::sk_check(sk), "zero secret key");
    let h = chia_h2c::hash_to_g2(msg);
    blst_ffi::sign_pk2_in_g1(sk, &h)
  }

  fn sign_with(_sk: &Self::InnerSk, _msg: &[u8], _scheme: super::BlsSigId) -> Result<Self::InnerSig, BlsError> {
    Err(BlsError::UnsupportedScheme)
  }

  fn verify(sig: &Self::InnerSig, msg: &[u8], pk: &Self::InnerPk) -> Result<(), BlsError> {
    if blst_ffi::p1_affine_is_inf(pk) {
      return Err(BlsError::InvalidPublicKey);
    }
    if blst_ffi::p2_affine_is_inf(sig) {
      return Err(BlsError::InvalidSignature);
    }

    let msg32: &[u8; 32] = msg.try_into().map_err(|_| BlsError::VerifyFailed)?;
    let h_proj = chia_h2c::hash_to_g2(msg32);
    if blst_ffi::pairings_equal_with_g1_generator(sig, &h_proj, pk) {
      Ok(())
    } else {
      Err(BlsError::VerifyFailed)
    }
  }

  fn verify_with(
    _sig: &Self::InnerSig,
    _msg: &[u8],
    _pk: &Self::InnerPk,
    _scheme: super::BlsSigId,
  ) -> Result<(), BlsError> {
    Err(BlsError::UnsupportedScheme)
  }

  fn prove_possession(_sk: &Self::InnerSk, _pk: &Self::InnerPk) -> Result<Self::InnerSig, BlsError> {
    Err(BlsError::UnsupportedScheme)
  }

  fn verify_possession(_pk: &Self::InnerPk, _pop: &Self::InnerSig) -> Result<(), BlsError> {
    Err(BlsError::UnsupportedScheme)
  }

  fn dh_exchange(sk: &Self::InnerSk, peer_pk: &Self::InnerPk) -> Result<Self::InnerPk, BlsError> {
    Ok(blst_ffi::p1_mult(peer_pk, &sk.b, blst_ffi::FR_BITS))
  }

  fn aggregate_pk(pks: &[&Self::InnerPk]) -> Result<Self::InnerPk, BlsError> {
    use crate::prelude::Vec;

    if pks.is_empty() {
      return Err(BlsError::EmptyAggregation);
    }
    let points: Vec<blst_p1_affine> = pks.iter().map(|pk| **pk).collect();
    Ok(blst_ffi::p1s_add(&points))
  }

  fn aggregate_sig(sigs: &[&Self::InnerSig]) -> Result<Self::InnerSig, BlsError> {
    use crate::prelude::Vec;

    if sigs.is_empty() {
      return Err(BlsError::EmptyAggregation);
    }
    let points: Vec<blst_p2_affine> = sigs.iter().map(|sig| **sig).collect();
    Ok(blst_ffi::p2s_add(&points))
  }

  fn fast_verify_aggregates(sig: &Self::InnerSig, msg: &[u8], pks: &[&Self::InnerPk]) -> Result<(), BlsError> {
    chia_verify_aggregates(sig, msg, pks)
  }

  fn verify_aggregates(_sig: &Self::InnerSig, _msgs: &[&[u8]], _pks: &[&Self::InnerPk]) -> Result<(), BlsError> {
    Err(BlsError::UnsupportedScheme)
  }

  fn secure_verify_aggregates(sig: &Self::InnerSig, msg: &[u8], pks: &[&Self::InnerPk]) -> Result<(), BlsError> {
    use crate::prelude::Vec;

    if pks.is_empty() {
      return Err(BlsError::EmptyAggregation);
    }

    let mut sorted: Vec<[u8; 48]> = pks.iter().map(|pk| Self::pk_to_bytes(pk)).collect();
    sorted.sort();

    let agg_pk = scheme_ops::weighted_g1_aggregate(&sorted, chia_deser_g1)?;
    Self::verify(sig, msg, &agg_pk)
  }

  fn recover_sig_shares(ids: &[&Hash256], sigs: &[&Self::InnerSig]) -> Result<Self::InnerSig, BlsError> {
    let sig_vals: crate::prelude::Vec<blst_p2_affine> = sigs.iter().map(|s| **s).collect();
    scheme_ops::recover_sig_shares_affine(ids, &sig_vals)
  }

  fn derive_pk_share(master_pks: &[&Self::InnerPk], id: &Hash256) -> Result<Self::InnerPk, BlsError> {
    let pk_vals: crate::prelude::Vec<blst_p1_affine> = master_pks.iter().map(|pk| **pk).collect();
    scheme_ops::derive_pk_share_affine(&pk_vals, id)
  }

  fn zeroize_sk(sk: &mut Self::InnerSk) {
    sk.zeroize();
  }
}

fn chia_verify_aggregates(sig: &blst_p2_affine, msg: &[u8], pks: &[&blst_p1_affine]) -> Result<(), BlsError> {
  if pks.is_empty() {
    return Err(BlsError::EmptyAggregation);
  }
  let agg_pk = <BlsScChia as BlsScheme>::aggregate_pk(pks)?;
  <BlsScChia as BlsScheme>::verify(sig, msg, &agg_pk)
}

// Chia legacy serialization helpers

fn chia_ser_g1(p: &blst_p1_affine) -> [u8; 48] {
  let ietf = blst_ffi::p1_affine_compress(p);

  if ietf[0] & 0xc0 == 0xc0 {
    return ietf;
  }

  let sign = (ietf[0] >> 5) & 1;
  let mut legacy = ietf;
  legacy[0] &= 0x1f;
  if sign == 1 {
    legacy[0] |= 0x80;
  }
  legacy
}

fn chia_deser_g1(bytes: &[u8; 48]) -> Result<blst_p1_affine, BlsError> {
  if bytes[0] & 0xc0 == 0xc0 {
    return if let Ok(out) = blst_ffi::p1_uncompress(bytes) {
      Ok(out)
    } else {
      Err(BlsError::InvalidPublicKey)
    };
  }

  let sign = (bytes[0] >> 7) & 1;
  let mut ietf = *bytes;
  ietf[0] &= 0x7f;
  ietf[0] |= 0x80;
  if sign == 1 {
    ietf[0] |= 0x20;
  }

  let out = blst_ffi::p1_uncompress(&ietf).map_err(|_| BlsError::InvalidPublicKey)?;
  if !blst_ffi::p1_affine_in_g1(&out) {
    return Err(BlsError::InvalidPublicKey);
  }
  Ok(out)
}

fn chia_ser_g2(p: &blst_p2_affine) -> [u8; 96] {
  let uncomp = blst_ffi::p2_affine_serialize(p);

  if uncomp.iter().all(|&b| b == 0) {
    let mut out = [0u8; 96];
    out[0] = 0xc0;
    return out;
  }

  let x_c1 = &uncomp[0..48];
  let x_c0 = &uncomp[48..96];
  let y_c1 = &uncomp[96..144];

  let sign = chia_y_c1_is_larger(y_c1);

  let mut legacy = [0u8; 96];
  legacy[..48].copy_from_slice(x_c0);
  legacy[48..96].copy_from_slice(x_c1);
  if sign {
    legacy[0] |= 0x80;
  }
  legacy
}

fn chia_deser_g2(bytes: &[u8; 96]) -> Result<blst_p2_affine, BlsError> {
  if bytes[0] & 0xc0 == 0xc0 {
    let mut ietf = [0u8; 96];
    ietf[0] = 0xc0;
    return if let Ok(out) = blst_ffi::p2_uncompress(&ietf) {
      Ok(out)
    } else {
      Err(BlsError::InvalidSignature)
    };
  }

  let sign = (bytes[0] >> 7) & 1;

  let mut x_c0 = [0u8; 48];
  x_c0.copy_from_slice(&bytes[..48]);
  x_c0[0] &= 0x7f;
  let x_c1 = &bytes[48..96];

  let mut ietf = [0u8; 96];
  ietf[..48].copy_from_slice(x_c1);
  ietf[48..96].copy_from_slice(&x_c0);

  ietf[0] |= 0x80;

  let mut out = blst_ffi::p2_uncompress(&ietf).map_err(|_| BlsError::InvalidSignature)?;
  if !blst_ffi::p2_affine_in_g2(&out) {
    return Err(BlsError::InvalidSignature);
  }

  let y_c1_bytes = Fp::from_raw(out.y.fp[1]).to_bendian();
  let decompressed_sign = chia_y_c1_is_larger(&y_c1_bytes);

  if (sign == 1) != decompressed_sign {
    out.y = (-Fp2::from_raw(out.y)).into_raw();
  }

  Ok(out)
}

fn chia_y_c1_is_larger(y_c1: &[u8]) -> bool {
  use hex_literal::hex;
  const HALF_P: [u8; 48] = hex!(
    "0d0088f5 1cbff34d 258dd3db 21a5d66b"
    "b23ba5c2 79c2895f b3986950 7b587b12"
    "0f55ffff 58a9ffff dcff7fff ffffd555"
  );

  y_c1.len() >= 48 && y_c1[..48] > HALF_P[..]
}
