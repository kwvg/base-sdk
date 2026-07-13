//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Benchmarks for the IETF BLS module.

use dash_pkc::bls_ietf::{
  aggregate_pk, aggregate_sig, fast_verify_aggregates, verify_aggregates, PublicKey, SecretKey, Signature,
};

/// Single signature creation.
#[divan::bench]
fn sign(bencher: divan::Bencher) {
  let sk = SecretKey::generate(&super::common::test_ikm(1)).unwrap();
  bencher
    .counter(divan::counter::ItemsCount::new(1u32))
    .bench(|| sk.sign(&super::common::test_msg(42)));
}

/// Single signature verification.
#[divan::bench]
fn verify(bencher: divan::Bencher) {
  let sk = SecretKey::generate(&super::common::test_ikm(2)).unwrap();
  let msg = super::common::test_msg(99);
  let sig = sk.sign(&msg);
  let pk = sk.public_key();
  bencher
    .counter(divan::counter::ItemsCount::new(1u32))
    .bench(|| sig.verify(&msg, &pk));
}

/// Public key aggregation at various quorum sizes.
#[divan::bench(args = [2, 5, 25, 50, 100])]
fn aggregate_pk_n(bencher: divan::Bencher, n: usize) {
  let pks: Vec<_> = (0..n)
    .map(|i| {
      SecretKey::generate(&super::common::test_ikm(i as u8))
        .unwrap()
        .public_key()
    })
    .collect();
  let pk_refs: Vec<_> = pks.iter().collect();
  bencher
    .counter(divan::counter::ItemsCount::new(n))
    .bench(|| aggregate_pk(&pk_refs));
}

/// Signature aggregation at various batch sizes.
#[divan::bench(args = [2, 10, 100])]
fn aggregate_sig_n(bencher: divan::Bencher, n: usize) {
  let keys: Vec<_> = (0..n)
    .map(|i| SecretKey::generate(&super::common::test_ikm(i as u8)).unwrap())
    .collect();
  let sigs: Vec<_> = keys
    .iter()
    .enumerate()
    .map(|(i, k)| k.sign(&super::common::test_msg(i as u8)))
    .collect();
  let sig_refs: Vec<&Signature> = sigs.iter().collect();
  bencher
    .counter(divan::counter::ItemsCount::new(n))
    .bench(|| aggregate_sig(&sig_refs));
}

/// N individual verifications in a loop.
#[divan::bench(args = [100, 1000])]
fn verify_n_individual(bencher: divan::Bencher, n: usize) {
  let keys: Vec<_> = (0..n)
    .map(|i| SecretKey::generate(&super::common::test_ikm(i as u8)).unwrap())
    .collect();
  let msgs: Vec<[u8; 32]> = (0..n).map(|i| super::common::test_msg(i as u8)).collect();
  let pks: Vec<_> = keys.iter().map(|k| k.public_key()).collect();
  let sigs: Vec<_> = keys.iter().zip(msgs.iter()).map(|(k, m)| k.sign(m)).collect();
  bencher.counter(divan::counter::ItemsCount::new(n)).bench(|| {
    for i in 0..n {
      let _ = sigs[i].verify(&msgs[i], &pks[i]);
    }
  });
}

/// Aggregate N signatures over distinct messages, then verify.
#[divan::bench(args = [10, 100, 1000])]
fn verify_aggregated_block(bencher: divan::Bencher, n: usize) {
  let keys: Vec<_> = (0..n)
    .map(|i| SecretKey::generate(&super::common::test_ikm(i as u8)).unwrap())
    .collect();
  let msgs: Vec<[u8; 32]> = (0..n).map(|i| super::common::test_msg(i as u8)).collect();
  let pks: Vec<_> = keys.iter().map(|k| k.public_key()).collect();
  let sigs: Vec<_> = keys.iter().zip(msgs.iter()).map(|(k, m)| k.sign(m)).collect();
  let sig_refs: Vec<&Signature> = sigs.iter().collect();
  let agg_sig = aggregate_sig(&sig_refs).unwrap();
  let pk_refs: Vec<_> = pks.iter().collect();
  let msg_slices: Vec<&[u8]> = msgs.iter().map(|m| m.as_slice()).collect();
  bencher
    .counter(divan::counter::ItemsCount::new(n))
    .bench(|| verify_aggregates(&agg_sig, &msg_slices, &pk_refs));
}

/// Fast aggregate verify (same message, N signers).
#[divan::bench(args = [10, 100, 1000])]
fn fast_verify_n(bencher: divan::Bencher, n: usize) {
  let keys: Vec<_> = (0..n)
    .map(|i| SecretKey::generate(&super::common::test_ikm(i as u8)).unwrap())
    .collect();
  let msg = super::common::test_msg(42);
  let pks: Vec<_> = keys.iter().map(|k| k.public_key()).collect();
  let sigs: Vec<_> = keys.iter().map(|k| k.sign(&msg)).collect();
  let sig_refs: Vec<&Signature> = sigs.iter().collect();
  let agg_sig = aggregate_sig(&sig_refs).unwrap();
  let pk_refs: Vec<_> = pks.iter().collect();
  bencher
    .counter(divan::counter::ItemsCount::new(n))
    .bench(|| fast_verify_aggregates(&agg_sig, &msg, &pk_refs));
}

/// Public key serialization (compress).
#[divan::bench]
fn ser_pk(bencher: divan::Bencher) {
  let pk = SecretKey::generate(&super::common::test_ikm(1)).unwrap().public_key();
  bencher.bench(|| pk.to_bytes());
}

/// Public key deserialization (decompress + validate).
#[divan::bench]
fn deser_pk(bencher: divan::Bencher) {
  let bytes = SecretKey::generate(&super::common::test_ikm(1))
    .unwrap()
    .public_key()
    .to_bytes();
  bencher.bench(|| PublicKey::from_bytes(&bytes));
}

/// Signature serialization (compress).
#[divan::bench]
fn ser_sig(bencher: divan::Bencher) {
  let sig = SecretKey::generate(&super::common::test_ikm(1))
    .unwrap()
    .sign(&super::common::test_msg(0));
  bencher.bench(|| sig.to_bytes());
}

/// Signature deserialization (decompress + validate).
#[divan::bench]
fn deser_sig(bencher: divan::Bencher) {
  let bytes = SecretKey::generate(&super::common::test_ikm(1))
    .unwrap()
    .sign(&super::common::test_msg(0))
    .to_bytes();
  bencher.bench(|| Signature::from_bytes(&bytes));
}

/// Threshold secret key splitting at various quorum sizes.
#[divan::bench(args = [5, 10, 50])]
fn split_threshold(bencher: divan::Bencher, n: usize) {
  use dash_pkc::bls_ietf::threshold;
  let sk = SecretKey::generate(&super::common::test_ikm(1)).unwrap();
  let t = n.div_ceil(2);
  let ids = super::common::sequential_ids(n);
  bencher
    .counter(divan::counter::ItemsCount::new(n))
    .bench(|| threshold::split_sk(&sk, t, &ids, &mut rand_core::OsRng));
}

/// Threshold signature recovery via Lagrange interpolation.
#[divan::bench(args = [3, 5, 10])]
fn recover_threshold(bencher: divan::Bencher, t: usize) {
  use dash_pkc::bls_ietf::threshold;
  let sk = SecretKey::generate(&super::common::test_ikm(1)).unwrap();
  let n = t * 2;
  let ids = super::common::sequential_ids(n);
  let shares = threshold::split_sk(&sk, t, &ids, &mut rand_core::OsRng).unwrap();
  let msg = super::common::test_msg(42);
  let sig_shares: Vec<_> = shares.iter().map(|s| s.sign(&msg)).collect();
  let subset: Vec<&threshold::SignatureShare> = sig_shares.iter().take(t).collect();
  bencher
    .counter(divan::counter::ItemsCount::new(t))
    .bench(|| threshold::recover_sig(&subset));
}

/// Proof of possession creation.
#[divan::bench]
fn prove_pop(bencher: divan::Bencher) {
  let sk = SecretKey::generate(&super::common::test_ikm(1)).unwrap();
  bencher.bench(|| sk.prove_possession().unwrap());
}

/// Proof of possession verification.
#[divan::bench]
fn verify_pop(bencher: divan::Bencher) {
  let sk = SecretKey::generate(&super::common::test_ikm(1)).unwrap();
  let pop = sk.prove_possession().unwrap();
  let pk = sk.public_key();
  bencher.bench(|| pk.verify_possession(&pop));
}

#[cfg(feature = "std")]
mod worker_benches {
  use dash_pkc::bls_ietf::{aggregate_pk, PublicKey, SecretKey, Signature};
  use dash_pkc::worker;

  fn setup_sigs(n: usize) -> Vec<(Signature, PublicKey, Vec<u8>)> {
    (0..n)
      .map(|i| {
        let sk = SecretKey::generate(&super::super::common::test_ikm(i as u8)).unwrap();
        let msg = super::super::common::test_msg(i as u8);
        let pk = sk.public_key();
        let sig = sk.sign(&msg);
        (sig, pk, msg.to_vec())
      })
      .collect()
  }

  #[divan::bench(args = [100, 1000])]
  fn worker_verify_n(bencher: divan::Bencher, n: usize) {
    let tuples = setup_sigs(n);
    bencher
      .counter(divan::counter::ItemsCount::new(n))
      .bench(|| worker::par_verify(&tuples, |(sig, pk, msg)| sig.verify(msg, pk).is_ok()));
  }

  #[divan::bench(args = [100, 1000])]
  fn worker_aggregate_pk_n(bencher: divan::Bencher, n: usize) {
    let pks: Vec<PublicKey> = (0..n)
      .map(|i| {
        SecretKey::generate(&super::super::common::test_ikm(i as u8))
          .unwrap()
          .public_key()
      })
      .collect();
    bencher
      .counter(divan::counter::ItemsCount::new(n))
      .bench(|| worker::par_reduce(pks.clone(), |a, b| aggregate_pk(&[&a, &b]).unwrap()));
  }
}
