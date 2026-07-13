//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

//! Benchmarks for the IETF BLS module.

use dash_pkc::bls::{BlsPublicKey, BlsScIetf, BlsSecretKey, BlsSignature};
use dash_pkc::tests::{sequential_ids, test_ikm, test_msg};
use divan::{bench, counter::ItemsCount, Bencher};
use rand_core::OsRng;

type SecretKey = BlsSecretKey<BlsScIetf>;
type PublicKey = BlsPublicKey<BlsScIetf>;
type Signature = BlsSignature<BlsScIetf>;

/// Single signature creation.
#[bench]
fn sign(bencher: Bencher) {
  let sk = SecretKey::generate(&test_ikm(1)).unwrap();
  bencher.counter(ItemsCount::new(1u32)).bench(|| sk.sign(&test_msg(42)));
}

/// Single signature verification.
#[bench]
fn verify(bencher: Bencher) {
  let sk = SecretKey::generate(&test_ikm(2)).unwrap();
  let msg = test_msg(99);
  let sig = sk.sign(&msg);
  let pk = sk.public_key();
  bencher.counter(ItemsCount::new(1u32)).bench(|| sig.verify(&msg, &pk));
}

/// Public key aggregation at various quorum sizes.
#[bench(args = [2, 5, 25, 50, 100])]
fn aggregate_pk_n(bencher: Bencher, n: usize) {
  let pks: Vec<_> = (0..n)
    .map(|i| SecretKey::generate(&test_ikm(i as u8)).unwrap().public_key())
    .collect();
  let pk_refs: Vec<_> = pks.iter().collect();
  bencher
    .counter(ItemsCount::new(n))
    .bench(|| PublicKey::aggregate(&pk_refs));
}

/// Signature aggregation at various batch sizes.
#[bench(args = [2, 10, 100])]
fn aggregate_sig_n(bencher: Bencher, n: usize) {
  let keys: Vec<_> = (0..n)
    .map(|i| SecretKey::generate(&test_ikm(i as u8)).unwrap())
    .collect();
  let sigs: Vec<_> = keys
    .iter()
    .enumerate()
    .map(|(i, k)| k.sign(&test_msg(i as u8)))
    .collect();
  let sig_refs: Vec<&Signature> = sigs.iter().collect();
  bencher
    .counter(ItemsCount::new(n))
    .bench(|| Signature::aggregate(&sig_refs));
}

/// N individual verifications in a loop.
#[bench(args = [100, 1000])]
fn verify_n_individual(bencher: Bencher, n: usize) {
  let keys: Vec<_> = (0..n)
    .map(|i| SecretKey::generate(&test_ikm(i as u8)).unwrap())
    .collect();
  let msgs: Vec<[u8; 32]> = (0..n).map(|i| test_msg(i as u8)).collect();
  let pks: Vec<_> = keys.iter().map(|k| k.public_key()).collect();
  let sigs: Vec<_> = keys.iter().zip(msgs.iter()).map(|(k, m)| k.sign(m)).collect();
  bencher.counter(ItemsCount::new(n)).bench(|| {
    for i in 0..n {
      let _ = sigs[i].verify(&msgs[i], &pks[i]);
    }
  });
}

/// Aggregate N signatures over distinct messages, then verify.
#[bench(args = [10, 100, 1000])]
fn verify_aggregated_block(bencher: Bencher, n: usize) {
  let keys: Vec<_> = (0..n)
    .map(|i| SecretKey::generate(&test_ikm(i as u8)).unwrap())
    .collect();
  let msgs: Vec<[u8; 32]> = (0..n).map(|i| test_msg(i as u8)).collect();
  let pks: Vec<_> = keys.iter().map(|k| k.public_key()).collect();
  let sigs: Vec<_> = keys.iter().zip(msgs.iter()).map(|(k, m)| k.sign(m)).collect();
  let sig_refs: Vec<&Signature> = sigs.iter().collect();
  let agg_sig = Signature::aggregate(&sig_refs).unwrap();
  let pk_refs: Vec<_> = pks.iter().collect();
  let msg_slices: Vec<&[u8]> = msgs.iter().map(|m| m.as_slice()).collect();
  bencher
    .counter(ItemsCount::new(n))
    .bench(|| agg_sig.verify_aggregates(&msg_slices, &pk_refs));
}

/// Fast aggregate verify (same message, N signers).
#[bench(args = [10, 100, 1000])]
fn fast_verify_n(bencher: Bencher, n: usize) {
  let keys: Vec<_> = (0..n)
    .map(|i| SecretKey::generate(&test_ikm(i as u8)).unwrap())
    .collect();
  let msg = test_msg(42);
  let pks: Vec<_> = keys.iter().map(|k| k.public_key()).collect();
  let sigs: Vec<_> = keys.iter().map(|k| k.sign(&msg)).collect();
  let sig_refs: Vec<&Signature> = sigs.iter().collect();
  let agg_sig = Signature::aggregate(&sig_refs).unwrap();
  let pk_refs: Vec<_> = pks.iter().collect();
  bencher
    .counter(ItemsCount::new(n))
    .bench(|| agg_sig.fast_verify_aggregates(&msg, &pk_refs));
}

/// Public key serialization (compress).
#[bench]
fn ser_pk(bencher: Bencher) {
  let pk = SecretKey::generate(&test_ikm(1)).unwrap().public_key();
  bencher.bench(|| pk.to_bytes());
}

/// Public key deserialization (decompress + validate).
#[bench]
fn deser_pk(bencher: Bencher) {
  let bytes = SecretKey::generate(&test_ikm(1)).unwrap().public_key().to_bytes();
  bencher.bench(|| PublicKey::from_bytes(&bytes));
}

/// Signature serialization (compress).
#[bench]
fn ser_sig(bencher: Bencher) {
  let sig = SecretKey::generate(&test_ikm(1)).unwrap().sign(&test_msg(0));
  bencher.bench(|| sig.to_bytes());
}

/// Signature deserialization (decompress + validate).
#[bench]
fn deser_sig(bencher: Bencher) {
  let bytes = SecretKey::generate(&test_ikm(1)).unwrap().sign(&test_msg(0)).to_bytes();
  bencher.bench(|| Signature::from_bytes(&bytes));
}

/// Threshold secret key splitting at various quorum sizes.
#[bench(args = [5, 10, 50])]
fn split_threshold(bencher: Bencher, n: usize) {
  let sk = SecretKey::generate(&test_ikm(1)).unwrap();
  let t = n.div_ceil(2);
  let ids = sequential_ids(n);
  bencher
    .counter(ItemsCount::new(n))
    .bench(|| sk.split(t, &ids, &mut OsRng));
}

/// Threshold signature recovery via Lagrange interpolation.
#[bench(args = [3, 5, 10])]
fn recover_threshold(bencher: Bencher, t: usize) {
  use dash_pkc::bls::BlsSigShare;
  let sk = SecretKey::generate(&test_ikm(1)).unwrap();
  let n = t * 2;
  let ids = sequential_ids(n);
  let shares = sk.split(t, &ids, &mut OsRng).unwrap();
  let msg = test_msg(42);
  let sig_shares: Vec<_> = shares.iter().map(|s| s.sign(&msg)).collect();
  let subset: Vec<&BlsSigShare<BlsScIetf>> = sig_shares.iter().take(t).collect();
  bencher
    .counter(ItemsCount::new(t))
    .bench(|| Signature::recover(&subset));
}

/// Proof of possession creation.
#[bench]
fn prove_pop(bencher: Bencher) {
  let sk = SecretKey::generate(&test_ikm(1)).unwrap();
  bencher.bench(|| sk.prove_possession());
}

/// Proof of possession verification.
#[bench]
fn verify_pop(bencher: Bencher) {
  let sk = SecretKey::generate(&test_ikm(1)).unwrap();
  let pop = sk.prove_possession().unwrap();
  let pk = sk.public_key();
  bencher.bench(|| pk.verify_possession(&pop));
}

#[cfg(feature = "std")]
mod worker_benches {
  use dash_pkc::bls::{BlsPublicKey, BlsScIetf, BlsSecretKey, BlsSignature};
  use dash_pkc::tests::{test_ikm, test_msg};
  use dash_pkc::worker;
  use divan::{bench, counter::ItemsCount, Bencher};

  type SecretKey = BlsSecretKey<BlsScIetf>;
  type PublicKey = BlsPublicKey<BlsScIetf>;
  type Signature = BlsSignature<BlsScIetf>;

  fn setup_sigs(n: usize) -> Vec<(Signature, PublicKey, Vec<u8>)> {
    (0..n)
      .map(|i| {
        let sk = SecretKey::generate(&test_ikm(i as u8)).unwrap();
        let msg = test_msg(i as u8);
        let pk = sk.public_key();
        let sig = sk.sign(&msg);
        (sig, pk, msg.to_vec())
      })
      .collect()
  }

  #[bench(args = [100, 1000])]
  fn worker_verify_n(bencher: Bencher, n: usize) {
    let tuples = setup_sigs(n);
    bencher
      .counter(ItemsCount::new(n))
      .bench(|| worker::par_verify(&tuples, |(sig, pk, msg)| sig.verify(msg, pk).is_ok()));
  }

  #[bench(args = [100, 1000])]
  fn worker_aggregate_pk_n(bencher: Bencher, n: usize) {
    let pks: Vec<PublicKey> = (0..n)
      .map(|i| SecretKey::generate(&test_ikm(i as u8)).unwrap().public_key())
      .collect();
    bencher
      .counter(ItemsCount::new(n))
      .bench(|| worker::par_reduce(pks.clone(), |a, b| PublicKey::aggregate(&[&a, &b]).unwrap()));
  }
}
