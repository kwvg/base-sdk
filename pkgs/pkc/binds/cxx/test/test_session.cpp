//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

#define BOOST_TEST_MODULE dashpkc_session
#include <boost/test/included/unit_test.hpp>

#include <cstdint>
#include <vector>

#include <dashpkc/dashpkc.h>

namespace {

std::vector<uint8_t> Seq(size_t n, uint8_t start)
{
  std::vector<uint8_t> out(n);
  for (size_t i = 0; i < n; ++i) {
    out[i] = static_cast<uint8_t>(start + i);
  }
  return out;
}

} // namespace

BOOST_AUTO_TEST_CASE(session_matches_uncached_paths)
{
  auto session = dash_pkc::Session::Create(Seq(32, 0xE0));
  BOOST_REQUIRE(session.has_value());
  BOOST_CHECK(!dash_pkc::Session::Create(Seq(16, 0)).has_value());

  auto sk = dash_pkc::PrivateKey::KeyGen(Seq(32, 0x91));
  BOOST_REQUIRE(sk.has_value());
  const auto hash = Seq(32, 0x92);

  for (const bool legacy : {false, true}) {
    auto pk = sk->GetG1Element(legacy);
    auto sig = sk->Sign(hash, legacy);
    BOOST_REQUIRE(pk.has_value());
    BOOST_REQUIRE(sig.has_value());

    // Repeated session verifies exercise the hash-to-G2, then the
    // result cache; all must agree with the uncached path.
    for (int rep = 0; rep < 3; ++rep) {
      BOOST_CHECK(session->Verify(*pk, hash, *sig, legacy));
    }
    BOOST_CHECK(!session->Verify(*pk, Seq(32, 0x93), *sig, legacy));
    BOOST_CHECK(
        session->Verify(*pk, hash, *sig, legacy) ==
        dash_pkc::CoreMPL(legacy).Verify(*pk, hash, *sig)
    );

    auto sk2 = dash_pkc::PrivateKey::KeyGen(Seq(32, 0x94));
    const auto hash2 = Seq(32, 0x95);
    auto sig2 = sk2->Sign(hash2, legacy);
    auto agg = dash_pkc::CoreMPL(legacy).Aggregate(*sig, *sig2);
    BOOST_REQUIRE(agg.has_value());
    const std::vector<dash_pkc::G1Element> pks{*pk, *sk2->GetG1Element(legacy)};
    const std::vector<std::vector<uint8_t>> msgs{hash, hash2};
    for (int rep = 0; rep < 2; ++rep) {
      BOOST_CHECK(session->VerifyAggregated(pks, msgs, *agg, legacy));
    }
    BOOST_CHECK(!session->VerifyAggregated(pks, {hash2, hash}, *agg, legacy));

    // Parse caches return equal objects on repeated inputs.
    const auto pkBytes = pk->SerializeToArray(legacy);
    auto p1 = session->ParsePublicKey(pkBytes, legacy);
    auto p2 = session->ParsePublicKey(pkBytes, legacy);
    BOOST_REQUIRE(p1.has_value());
    BOOST_REQUIRE(p2.has_value());
    BOOST_CHECK(*p1 == *p2);
    BOOST_CHECK(*p1 == *pk);
    BOOST_CHECK(session->ParseSignature(sig->SerializeToArray(legacy), legacy).has_value());

    // Secure verification via the weighted-aggregate cache.
    const std::vector<dash_pkc::G2Element> memberSigs{
        *sk->Sign(hash, legacy), *sk2->Sign(hash, legacy)
    };
    auto secure = session->AggregateSecure(pks, memberSigs, legacy);
    BOOST_REQUIRE(secure.has_value());
    for (int rep = 0; rep < 2; ++rep) {
      BOOST_CHECK(session->VerifySecure(pks, *secure, hash, legacy));
    }
    BOOST_CHECK(dash_pkc::CoreMPL(legacy).VerifySecure(pks, *secure, hash));
  }
}

BOOST_AUTO_TEST_CASE(session_threshold_recovery)
{
  auto session = dash_pkc::Session::Create(Seq(32, 0xE1));
  BOOST_REQUIRE(session.has_value());

  for (const bool legacy : {false, true}) {
    std::vector<dash_pkc::PrivateKey> masterSks;
    std::vector<dash_pkc::G1Element> masterPks;
    for (uint8_t i = 1; i <= 2; ++i) {
      auto sk =
          dash_pkc::PrivateKey::KeyGen(std::vector<uint8_t>(32, static_cast<uint8_t>(0x50 + i)));
      BOOST_REQUIRE(sk.has_value());
      masterPks.push_back(*sk->GetG1Element(legacy));
      masterSks.push_back(std::move(*sk));
    }

    const auto hash = Seq(32, 0x60);
    std::vector<std::vector<uint8_t>> ids;
    std::vector<dash_pkc::G2Element> shareSigs;
    for (uint8_t i = 1; i <= 2; ++i) {
      std::vector<uint8_t> id(32, 0);
      id[0] = i;
      auto skShare = dash_pkc::Threshold::PrivateKeyShare(masterSks, id);
      auto pkShare = session->PublicKeyShare(masterPks, id);
      BOOST_REQUIRE(skShare.has_value());
      BOOST_REQUIRE(pkShare.has_value());
      BOOST_CHECK(*skShare->GetG1Element(legacy) == *pkShare);
      shareSigs.push_back(*skShare->Sign(hash, legacy));
      ids.push_back(id);
    }

    // Repeated recovery hits the Lagrange coefficient cache and
    // must agree with the uncached path.
    auto r1 = session->SignatureRecover(shareSigs, ids);
    auto r2 = session->SignatureRecover(shareSigs, ids);
    auto plain = dash_pkc::Threshold::SignatureRecover(shareSigs, ids);
    BOOST_REQUIRE(r1.has_value());
    BOOST_REQUIRE(r2.has_value());
    BOOST_REQUIRE(plain.has_value());
    BOOST_CHECK(*r1 == *r2);
    BOOST_CHECK(*r1 == *plain);
    BOOST_CHECK(dash_pkc::CoreMPL(legacy).Verify(masterPks[0], hash, *r1));
  }
}
