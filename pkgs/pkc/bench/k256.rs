//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Benchmarks for the k256 (secp256k1) feature

use dash_pkc::ecdsa::{EcdsaPublicKey, EcdsaSecretKey};

fn test_key() -> EcdsaSecretKey {
  let bytes = [
    0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba,
    0x98, 0x76, 0x54, 0x32, 0x10, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
  ];
  EcdsaSecretKey::from_bytes(&bytes).unwrap()
}

fn test_msg_hash(i: u8) -> [u8; 32] {
  let mut h = [0u8; 32];
  h[0] = i;
  h[31] = i.wrapping_mul(37);
  h
}

#[divan::bench]
fn sign(bencher: divan::Bencher) {
  let sk = test_key();
  bencher.counter(divan::counter::ItemsCount::new(1u32)).bench(|| {
    let msg = test_msg_hash(42);
    sk.sign(&msg).unwrap()
  });
}

#[divan::bench]
fn verify(bencher: divan::Bencher) {
  let sk = test_key();
  let msg = test_msg_hash(99);
  let sig = sk.sign(&msg).unwrap();
  let pk = sk.public_key();
  bencher
    .counter(divan::counter::ItemsCount::new(1u32))
    .bench(|| pk.verify(&msg, &sig));
}

#[divan::bench]
fn sign_recoverable(bencher: divan::Bencher) {
  let sk = test_key();
  bencher
    .counter(divan::counter::ItemsCount::new(1u32))
    .bench(|| sk.sign_recoverable(&test_msg_hash(7)).unwrap());
}

#[divan::bench]
fn recover(bencher: divan::Bencher) {
  let sk = test_key();
  let msg = test_msg_hash(55);
  let (sig, rid) = sk.sign_recoverable(&msg).unwrap();
  bencher
    .counter(divan::counter::ItemsCount::new(1u32))
    .bench(|| EcdsaPublicKey::recover(&msg, &sig, rid));
}

#[divan::bench]
fn ser_pk(bencher: divan::Bencher) {
  let pk = test_key().public_key();
  bencher.bench(|| pk.to_bytes());
}

#[divan::bench]
fn deser_pk(bencher: divan::Bencher) {
  let bytes = test_key().public_key().to_bytes();
  bencher.bench(|| EcdsaPublicKey::from_bytes(&bytes));
}

#[cfg(feature = "std")]
mod worker_benches {
  use dash_pkc::ecdsa::{EcdsaPublicKey, EcdsaSecretKey, EcdsaSignature};
  use dash_pkc::worker;

  fn setup_sigs(n: usize) -> Vec<(EcdsaSignature, EcdsaPublicKey, [u8; 32])> {
    let sk = EcdsaSecretKey::from_bytes(&[0x42u8; 32]).unwrap();
    let pk = sk.public_key();
    (0..n)
      .map(|i| {
        let mut msg = [0u8; 32];
        msg[0] = i as u8;
        msg[31] = (i >> 8) as u8;
        let sig = sk.sign(&msg).unwrap();
        (sig, pk.clone(), msg)
      })
      .collect()
  }

  #[divan::bench(args = [100, 1000])]
  fn worker_verify_n(bencher: divan::Bencher, n: usize) {
    let tuples = setup_sigs(n);
    bencher
      .counter(divan::counter::ItemsCount::new(n))
      .bench(|| worker::par_verify(&tuples, |(sig, pk, msg)| pk.verify(msg, sig).is_ok()));
  }
}
