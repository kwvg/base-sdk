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
use super::BlsSigId;
use crate::prelude::*;

use blst::min_pk::SecretKey;
use blst::{blst_p1_affine, blst_p2_affine, blst_scalar};
use dash_num::Hash256;
use zeroize::Zeroize;

impl BlsScheme for BlsScChia {
  type InnerSk = blst_scalar;
  type InnerPk = blst_p1_affine;
  type InnerSig = blst_p2_affine;

  fn generate(ikm: &[u8]) -> Result<Self::InnerSk, BlsError> {
    let sk = SecretKey::key_gen(ikm, &[]).map_err(|_| BlsError::InvalidKeyMaterial)?;
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

  fn pk_to_ietf_bytes(pk: &Self::InnerPk) -> [u8; 48] {
    blst_ffi::p1_affine_compress(pk)
  }

  fn sig_from_bytes(b: &[u8; 96]) -> Result<Self::InnerSig, BlsError> {
    chia_deser_g2(b)
  }

  fn sig_to_bytes(sig: &Self::InnerSig) -> [u8; 96] {
    chia_ser_g2(sig)
  }

  fn sign(sk: &Self::InnerSk, msg: &[u8]) -> Result<Self::InnerSig, BlsError> {
    debug_assert!(blst_ffi::sk_check(sk), "zero secret key");
    // dashbls signs 32-byte hashes only; the previous double-SHA
    // fallback produced signatures verify could never accept.
    let msg32: &[u8; 32] = msg.try_into().map_err(|_| BlsError::InvalidMessageLength)?;
    let h = chia_h2c::hash_to_g2(msg32);
    Ok(blst_ffi::sign_pk2_in_g1(sk, &h))
  }

  fn sign_with(_sk: &Self::InnerSk, _msg: &[u8], _scheme: BlsSigId) -> Result<Self::InnerSig, BlsError> {
    Err(BlsError::UnsupportedScheme)
  }

  fn verify(sig: &Self::InnerSig, msg: &[u8], pk: &Self::InnerPk) -> Result<(), BlsError> {
    if blst_ffi::p1_affine_is_inf(pk) {
      return Err(BlsError::InvalidPublicKey);
    }
    if blst_ffi::p2_affine_is_inf(sig) {
      return Err(BlsError::InvalidSignature);
    }

    let msg32: &[u8; 32] = msg.try_into().map_err(|_| BlsError::InvalidMessageLength)?;
    let h_proj = chia_h2c::hash_to_g2(msg32);
    if blst_ffi::pairings_equal_with_g1_generator(sig, &h_proj, pk) {
      Ok(())
    } else {
      Err(BlsError::VerifyFailed)
    }
  }

  fn verify_with(_sig: &Self::InnerSig, _msg: &[u8], _pk: &Self::InnerPk, _scheme: BlsSigId) -> Result<(), BlsError> {
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
    let agg = blst_ffi::p1s_add(&points);
    // Keys can cancel to infinity; an infinity aggregate is not a
    // usable public key (Dash Core treats it as invalid).
    if blst_ffi::p1_affine_is_inf(&agg) {
      return Err(BlsError::InvalidPublicKey);
    }
    Ok(agg)
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
    if pks.is_empty() {
      return Err(BlsError::EmptyAggregation);
    }

    // Pair each legacy encoding (the weight-derivation input)
    // with the point we already hold instead of re-deriving it
    // through a square root and subgroup check per key.
    let mut sorted: Vec<([u8; 48], blst_p1_affine)> = pks.iter().map(|pk| (Self::pk_to_bytes(pk), **pk)).collect();
    sorted.sort_by_key(|pair| pair.0);

    let agg_pk = scheme_ops::weighted_g1_aggregate(&sorted)?;
    Self::verify(sig, msg, &agg_pk)
  }

  fn recover_sig_shares(ids: &[&Hash256], sigs: &[&Self::InnerSig]) -> Result<Self::InnerSig, BlsError> {
    let sig_vals: Vec<blst_p2_affine> = sigs.iter().map(|s| **s).collect();
    let recovered = scheme_ops::recover_sig_shares_affine(ids, &sig_vals)?;
    // An infinity result is not a usable signature.
    if blst_ffi::p2_affine_is_inf(&recovered) {
      return Err(BlsError::InvalidSignature);
    }
    Ok(recovered)
  }

  fn derive_pk_share(master_pks: &[&Self::InnerPk], id: &Hash256) -> Result<Self::InnerPk, BlsError> {
    let pk_vals: Vec<blst_p1_affine> = master_pks.iter().map(|pk| **pk).collect();
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
  // Both tag bits set can only encode infinity, which Dash Core
  // rejects as a public key at parse (CBLSWrapper::SetBytes).
  if bytes[0] & 0xc0 == 0xc0 {
    return Err(BlsError::InvalidPublicKey);
  }

  // In the legacy format only bit 0x80 is a flag; bits 0x40/0x20
  // belong to x and imply x >= p, which dashbls rejects via the
  // relic range check. Reject before they reach the flag byte.
  if bytes[0] & 0x60 != 0 {
    return Err(BlsError::InvalidPublicKey);
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
  // Both tag bits set can only encode infinity. The previous
  // branch canonicalized 2^766 encodings to the infinity point;
  // Dash Core rejects infinity signatures at parse
  // (CBLSWrapper::SetBytes) and requires canonical encodings.
  if bytes[0] & 0xc0 == 0xc0 {
    return Err(BlsError::InvalidSignature);
  }

  // Byte 48 is the top byte of x.c1 and lands in the IETF flag
  // position after swizzling; any of its top 3 bits implies
  // x.c1 >= p, which dashbls rejects via the relic range check.
  if bytes[48] & 0xe0 != 0 {
    return Err(BlsError::InvalidSignature);
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
#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "test code")]
mod tests {
  use super::*;

  use dash_dev::{bls_sig_serialization, load_corpus_json};
  use rstest::rstest;

  #[rstest]
  fn signature_serialization_matches_vectors() {
    let corpus = load_corpus_json(env!("CARGO_MANIFEST_DIR"), "bls_chia_ser_internals");
    let vecs = bls_sig_serialization(&corpus, "sig_serialization");

    for v in &vecs {
      let sig = BlsScChia::sig_from_bytes(&v.legacy).unwrap();
      assert_eq!(BlsScChia::sig_to_bytes(&sig), v.legacy);
    }
  }

  #[rstest]
  #[case::x_bit_0x40(0x40)]
  #[case::x_bit_0x20(0x20)]
  #[case::sign_and_x_bit(0xa0)]
  fn g1_rejects_stray_flag_bits(#[case] first: u8) {
    // With bit 0x40 the old translation produced the canonical
    // IETF infinity encoding, silently accepting an infinity pk.
    let mut b = [0u8; 48];
    b[0] = first;
    assert_eq!(chia_deser_g1(&b).unwrap_err(), BlsError::InvalidPublicKey);
  }

  #[rstest]
  #[case::x_c1_bit_0x40(0x40)]
  #[case::x_c1_bit_0x20(0x20)]
  #[case::x_c1_bit_0x80(0x80)]
  fn g2_rejects_stray_x_c1_top_bits(#[case] byte48: u8) {
    // Byte 48 lands in the IETF flag position after swizzling;
    // 0x40 there decoded to canonical infinity before the fix.
    let mut b = [0u8; 96];
    b[48] = byte48;
    assert_eq!(chia_deser_g2(&b).unwrap_err(), BlsError::InvalidSignature);
  }
}
