//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Benchmarks for BLS schemes.

use dash_pkc::bls::{BlsPublicKey, BlsScChia, BlsScIetf, BlsScheme, BlsSecretKey, BlsSigShare, BlsSignature};
use dash_pkc::tests::{sequential_ids, test_ikm, test_msg};
use divan::{counter::ItemsCount, Bencher};
use rand_core::OsRng;

/// Single signature creation.
#[divan::bench(types = [BlsScChia, BlsScIetf])]
fn sign<S: BlsScheme>(bencher: Bencher) {
  let sk = BlsSecretKey::<S>::generate(&test_ikm(1)).unwrap();
  bencher.counter(ItemsCount::new(1u32)).bench(|| sk.sign(&test_msg(42)));
}

/// Single signature verification.
#[divan::bench(types = [BlsScChia, BlsScIetf])]
fn verify<S: BlsScheme>(bencher: Bencher) {
  let sk = BlsSecretKey::<S>::generate(&test_ikm(2)).unwrap();
  let msg = test_msg(99);
  let sig = sk.sign(&msg);
  let pk = sk.public_key();
  bencher.counter(ItemsCount::new(1u32)).bench(|| sig.verify(&msg, &pk));
}

/// Public key aggregation at various quorum sizes.
#[divan::bench(types = [BlsScChia, BlsScIetf], args = [2, 5, 25, 50, 100])]
fn aggregate_pk_n<S: BlsScheme>(bencher: Bencher, n: usize) {
  let pks: Vec<_> = (0..n)
    .map(|i| BlsSecretKey::<S>::generate(&test_ikm(i as u8)).unwrap().public_key())
    .collect();
  let pk_refs: Vec<_> = pks.iter().collect();
  bencher
    .counter(ItemsCount::new(n))
    .bench(|| BlsPublicKey::<S>::aggregate(&pk_refs));
}

/// Signature aggregation at various batch sizes.
#[divan::bench(types = [BlsScChia, BlsScIetf], args = [2, 10, 100])]
fn aggregate_sig_n<S: BlsScheme>(bencher: Bencher, n: usize) {
  let keys: Vec<_> = (0..n)
    .map(|i| BlsSecretKey::<S>::generate(&test_ikm(i as u8)).unwrap())
    .collect();
  let sigs: Vec<_> = keys
    .iter()
    .enumerate()
    .map(|(i, key)| key.sign(&test_msg(i as u8)))
    .collect();
  let sig_refs: Vec<&BlsSignature<S>> = sigs.iter().collect();
  bencher
    .counter(ItemsCount::new(n))
    .bench(|| BlsSignature::<S>::aggregate(&sig_refs));
}

/// N individual verifications in a loop.
#[divan::bench(types = [BlsScChia, BlsScIetf], args = [100, 1000])]
fn verify_n_individual<S: BlsScheme>(bencher: Bencher, n: usize) {
  let keys: Vec<_> = (0..n)
    .map(|i| BlsSecretKey::<S>::generate(&test_ikm(i as u8)).unwrap())
    .collect();
  let msgs: Vec<[u8; 32]> = (0..n).map(|i| test_msg(i as u8)).collect();
  let pks: Vec<_> = keys.iter().map(BlsSecretKey::public_key).collect();
  let sigs: Vec<_> = keys.iter().zip(&msgs).map(|(key, msg)| key.sign(msg)).collect();

  bencher.counter(ItemsCount::new(n)).bench(|| {
    for i in 0..n {
      let _ = sigs[i].verify(&msgs[i], &pks[i]);
    }
  });
}

/// Fast aggregate verification over a shared message.
#[divan::bench(types = [BlsScChia, BlsScIetf], args = [10, 100, 1000])]
fn fast_verify_n<S: BlsScheme>(bencher: Bencher, n: usize) {
  let keys: Vec<_> = (0..n)
    .map(|i| BlsSecretKey::<S>::generate(&test_ikm(i as u8)).unwrap())
    .collect();
  let msg = test_msg(42);
  let pks: Vec<_> = keys.iter().map(BlsSecretKey::public_key).collect();
  let sigs: Vec<_> = keys.iter().map(|key| key.sign(&msg)).collect();
  let sig_refs: Vec<&BlsSignature<S>> = sigs.iter().collect();
  let aggregate = BlsSignature::<S>::aggregate(&sig_refs).unwrap();
  let pk_refs: Vec<_> = pks.iter().collect();

  bencher
    .counter(ItemsCount::new(n))
    .bench(|| aggregate.fast_verify_aggregates(&msg, &pk_refs));
}

/// Public key serialization.
#[divan::bench(types = [BlsScChia, BlsScIetf])]
fn ser_pk<S: BlsScheme>(bencher: Bencher) {
  let pk = BlsSecretKey::<S>::generate(&test_ikm(1)).unwrap().public_key();
  bencher.bench(|| pk.to_bytes());
}

/// Public key deserialization.
#[divan::bench(types = [BlsScChia, BlsScIetf])]
fn deser_pk<S: BlsScheme>(bencher: Bencher) {
  let bytes = BlsSecretKey::<S>::generate(&test_ikm(1))
    .unwrap()
    .public_key()
    .to_bytes();
  bencher.bench(|| BlsPublicKey::<S>::from_bytes(&bytes));
}

/// Signature serialization.
#[divan::bench(types = [BlsScChia, BlsScIetf])]
fn ser_sig<S: BlsScheme>(bencher: Bencher) {
  let sig = BlsSecretKey::<S>::generate(&test_ikm(1)).unwrap().sign(&test_msg(0));
  bencher.bench(|| sig.to_bytes());
}

/// Signature deserialization.
#[divan::bench(types = [BlsScChia, BlsScIetf])]
fn deser_sig<S: BlsScheme>(bencher: Bencher) {
  let bytes = BlsSecretKey::<S>::generate(&test_ikm(1))
    .unwrap()
    .sign(&test_msg(0))
    .to_bytes();
  bencher.bench(|| BlsSignature::<S>::from_bytes(&bytes));
}

/// Threshold secret key splitting at various quorum sizes.
#[divan::bench(types = [BlsScChia, BlsScIetf], args = [5, 10, 50])]
fn split_threshold<S: BlsScheme>(bencher: Bencher, n: usize) {
  let sk = BlsSecretKey::<S>::generate(&test_ikm(1)).unwrap();
  let threshold = n.div_ceil(2);
  let ids = sequential_ids(n);
  bencher
    .counter(ItemsCount::new(n))
    .bench(|| sk.split(threshold, &ids, &mut OsRng));
}

/// Threshold signature recovery via Lagrange interpolation.
#[divan::bench(types = [BlsScChia, BlsScIetf], args = [3, 5, 10])]
fn recover_threshold<S: BlsScheme>(bencher: Bencher, threshold: usize) {
  let sk = BlsSecretKey::<S>::generate(&test_ikm(1)).unwrap();
  let ids = sequential_ids(threshold * 2);
  let shares = sk.split(threshold, &ids, &mut OsRng).unwrap();
  let msg = test_msg(42);
  let sig_shares: Vec<_> = shares.iter().map(|share| share.sign(&msg)).collect();
  let subset: Vec<&BlsSigShare<S>> = sig_shares.iter().take(threshold).collect();
  bencher
    .counter(ItemsCount::new(threshold))
    .bench(|| BlsSignature::<S>::recover(&subset));
}

/// IETF-only BLS operations.
mod ietf {
  use super::*;

  /// Aggregate signatures over distinct messages, then verify.
  #[divan::bench(args = [10, 100, 1000])]
  fn verify_aggregated_block(bencher: Bencher, n: usize) {
    let keys: Vec<_> = (0..n)
      .map(|i| BlsSecretKey::<BlsScIetf>::generate(&test_ikm(i as u8)).unwrap())
      .collect();
    let msgs: Vec<[u8; 32]> = (0..n).map(|i| test_msg(i as u8)).collect();
    let pks: Vec<_> = keys.iter().map(BlsSecretKey::public_key).collect();
    let sigs: Vec<_> = keys.iter().zip(&msgs).map(|(key, msg)| key.sign(msg)).collect();
    let sig_refs: Vec<&BlsSignature<BlsScIetf>> = sigs.iter().collect();
    let aggregate = BlsSignature::<BlsScIetf>::aggregate(&sig_refs).unwrap();
    let pk_refs: Vec<_> = pks.iter().collect();
    let msg_refs: Vec<&[u8]> = msgs.iter().map(|msg| msg.as_slice()).collect();

    bencher
      .counter(ItemsCount::new(n))
      .bench(|| aggregate.verify_aggregates(&msg_refs, &pk_refs));
  }

  /// Proof of possession creation.
  #[divan::bench]
  fn prove_pop(bencher: Bencher) {
    let sk = BlsSecretKey::<BlsScIetf>::generate(&test_ikm(1)).unwrap();
    bencher.bench(|| sk.prove_possession());
  }

  /// Proof of possession verification.
  #[divan::bench]
  fn verify_pop(bencher: Bencher) {
    let sk = BlsSecretKey::<BlsScIetf>::generate(&test_ikm(1)).unwrap();
    let pop = sk.prove_possession().unwrap();
    let pk = sk.public_key();
    bencher.bench(|| pk.verify_possession(&pop));
  }
}

#[cfg(feature = "std")]
mod worker {
  use super::*;
  use dash_pkc::worker;

  fn setup_sigs<S: BlsScheme>(n: usize) -> Vec<(BlsSignature<S>, BlsPublicKey<S>, [u8; 32])> {
    (0..n)
      .map(|i| {
        let sk = BlsSecretKey::<S>::generate(&test_ikm(i as u8)).unwrap();
        let msg = test_msg(i as u8);
        let pk = sk.public_key();
        let sig = sk.sign(&msg);
        (sig, pk, msg)
      })
      .collect()
  }

  #[divan::bench(types = [BlsScChia, BlsScIetf], args = [100, 1000])]
  fn verify_n<S: BlsScheme>(bencher: Bencher, n: usize)
  where
    BlsPublicKey<S>: Sync,
    BlsSignature<S>: Sync,
  {
    let tuples = setup_sigs::<S>(n);
    bencher
      .counter(ItemsCount::new(n))
      .bench(|| worker::par_verify(&tuples, |(sig, pk, msg)| sig.verify(msg, pk).is_ok()));
  }

  #[divan::bench(types = [BlsScChia, BlsScIetf], args = [100, 1000])]
  fn aggregate_pk_n<S: BlsScheme>(bencher: Bencher, n: usize)
  where
    BlsPublicKey<S>: Send,
  {
    let pks: Vec<BlsPublicKey<S>> = (0..n)
      .map(|i| BlsSecretKey::<S>::generate(&test_ikm(i as u8)).unwrap().public_key())
      .collect();
    bencher
      .counter(ItemsCount::new(n))
      .bench(|| worker::par_reduce(pks.clone(), |a, b| BlsPublicKey::<S>::aggregate(&[&a, &b]).unwrap()));
  }
}
