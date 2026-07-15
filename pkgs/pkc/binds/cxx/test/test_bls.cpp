//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

#define BOOST_TEST_MODULE dashpkc_bls
#include <boost/test/included/unit_test.hpp>

#include <algorithm>
#include <array>
#include <cstdint>
#include <string>
#include <vector>

#include <dashpkc/dashpkc.h>

namespace {

std::vector<uint8_t> FromHex(const std::string& hex)
{
  std::vector<uint8_t> out(hex.size() / 2);
  for (size_t i = 0; i < out.size(); ++i) {
    out[i] = static_cast<uint8_t>(std::stoul(hex.substr(2 * i, 2), nullptr, 16));
  }
  return out;
}

std::vector<uint8_t> Seq(size_t n, uint8_t start)
{
  std::vector<uint8_t> out(n);
  for (size_t i = 0; i < n; ++i) {
    out[i] = static_cast<uint8_t>(start + i);
  }
  return out;
}

constexpr std::array<bool, 2> kSchemes{false, true};

} // namespace

BOOST_AUTO_TEST_CASE(sign_verify_both_schemes)
{
  auto sk = dash_pkc::PrivateKey::KeyGen(Seq(32, 1));
  BOOST_REQUIRE(sk.has_value());

  const auto hash = Seq(32, 0x40);
  for (const bool legacy : kSchemes) {
    auto pk = sk->GetG1Element(legacy);
    auto sig = sk->Sign(hash, legacy);
    BOOST_REQUIRE(pk.has_value());
    BOOST_REQUIRE(sig.has_value());

    const dash_pkc::CoreMPL scheme(legacy);
    BOOST_CHECK(scheme.Verify(*pk, hash, *sig));
    BOOST_CHECK(!scheme.Verify(*pk, Seq(32, 0x41), *sig));
    BOOST_CHECK(!dash_pkc::CoreMPL(!legacy).Verify(*pk, hash, *sig));
  }

  // Legacy signing is hash-only, as in dashbls.
  auto bad = sk->Sign(Seq(31, 0), true);
  BOOST_REQUIRE(!bad.has_value());
  BOOST_CHECK(bad.error() == dash_pkc::Error::InvalidMessageLength);
  BOOST_CHECK(sk->Sign(Seq(31, 0), false).has_value());
}

BOOST_AUTO_TEST_CASE(serialization_round_trips)
{
  auto sk = dash_pkc::PrivateKey::KeyGen(Seq(32, 7));
  BOOST_REQUIRE(sk.has_value());

  const auto skBytes = sk->SerializeToArray();
  auto sk2 = dash_pkc::PrivateKey::FromBytes(skBytes);
  BOOST_REQUIRE(sk2.has_value());
  BOOST_CHECK(*sk2 == *sk);
  BOOST_CHECK(dash_pkc::PrivateKey::FromBytes(skBytes, /*modOrder=*/true).has_value());

  // Null objects: zero serialization, null equality, failing ops.
  dash_pkc::PrivateKey nullSk;
  dash_pkc::G1Element nullPk;
  BOOST_CHECK(nullSk.IsNull());
  BOOST_CHECK(nullPk == dash_pkc::G1Element{});
  BOOST_CHECK(nullPk != *sk->GetG1Element(false));
  const auto nullSer = nullPk.SerializeToArray(false);
  BOOST_CHECK(std::all_of(nullSer.begin(), nullSer.end(), [](uint8_t c) { return c == 0; }));
  BOOST_CHECK(!nullSk.Sign(Seq(32, 0), false).has_value());
  BOOST_CHECK(!dash_pkc::DHKeyExchange(nullSk, nullPk).has_value());

  // The same group element serializes differently per scheme but
  // parses back equal: the fork-transition reserialization path.
  auto pk = sk->GetG1Element(true);
  BOOST_REQUIRE(pk.has_value());
  const auto legacyBytes = pk->SerializeToArray(true);
  const auto basicBytes = pk->SerializeToArray(false);
  BOOST_CHECK(legacyBytes != basicBytes);

  auto fromLegacy = dash_pkc::G1Element::FromBytes(legacyBytes, true);
  auto fromBasic = dash_pkc::G1Element::FromBytes(basicBytes, false);
  BOOST_REQUIRE(fromLegacy.has_value());
  BOOST_REQUIRE(fromBasic.has_value());
  BOOST_CHECK(*fromLegacy == *fromBasic);
  BOOST_CHECK(*fromLegacy == *pk);

  const std::vector<uint8_t> zeros48(48, 0);
  BOOST_CHECK(!dash_pkc::G1Element::FromBytes(zeros48, false).has_value());
  BOOST_CHECK(!dash_pkc::G1Element::FromBytes(zeros48, true).has_value());
}

BOOST_AUTO_TEST_CASE(aggregation)
{
  for (const bool legacy : kSchemes) {
    const dash_pkc::CoreMPL scheme(legacy);
    const auto hash = Seq(32, 0x11);

    std::vector<dash_pkc::PrivateKey> sks;
    std::vector<dash_pkc::G1Element> pks;
    std::vector<dash_pkc::G2Element> sigs;
    for (uint8_t i = 1; i <= 3; ++i) {
      auto sk = dash_pkc::PrivateKey::KeyGen(std::vector<uint8_t>(32, i));
      BOOST_REQUIRE(sk.has_value());
      pks.push_back(*sk->GetG1Element(legacy));
      sigs.push_back(*sk->Sign(hash, legacy));
      sks.push_back(std::move(*sk));
    }

    auto aggPk = scheme.Aggregate(pks);
    auto aggSig = scheme.Aggregate(sigs);
    BOOST_REQUIRE(aggPk.has_value());
    BOOST_REQUIRE(aggSig.has_value());
    BOOST_CHECK(scheme.Verify(*aggPk, hash, *aggSig));

    auto secSig = scheme.AggregateSecure(pks, sigs, hash);
    BOOST_REQUIRE(secSig.has_value());
    BOOST_CHECK(scheme.VerifySecure(pks, *secSig, hash));
    BOOST_CHECK(!scheme.VerifySecure(pks, *aggSig, hash));

    auto aggSk = dash_pkc::PrivateKey::Aggregate(sks);
    BOOST_REQUIRE(aggSk.has_value());
    BOOST_CHECK(*aggSk->Sign(hash, legacy) == *aggSig);

    auto sub = aggSig->SubInsecure(sigs[2]);
    BOOST_REQUIRE(sub.has_value());
    auto pk01 = scheme.Aggregate(pks[0], pks[1]);
    BOOST_REQUIRE(pk01.has_value());
    BOOST_CHECK(scheme.Verify(*pk01, hash, *sub));

    std::vector<std::vector<uint8_t>> msgs;
    std::vector<dash_pkc::G2Element> msgSigs;
    for (uint8_t i = 0; i < 3; ++i) {
      msgs.push_back(Seq(32, static_cast<uint8_t>(0x20 + i)));
      msgSigs.push_back(*sks[i].Sign(msgs.back(), legacy));
    }
    auto agg2 = scheme.Aggregate(msgSigs);
    BOOST_REQUIRE(agg2.has_value());
    BOOST_CHECK(scheme.AggregateVerify(pks, msgs, *agg2));
    msgs[0][0] ^= 1;
    BOOST_CHECK(!scheme.AggregateVerify(pks, msgs, *agg2));
  }
}

BOOST_AUTO_TEST_CASE(threshold_flow)
{
  for (const bool legacy : kSchemes) {
    const dash_pkc::CoreMPL scheme(legacy);
    const auto hash = Seq(32, 0x77);

    std::vector<dash_pkc::PrivateKey> masterSks;
    std::vector<dash_pkc::G1Element> masterPks;
    for (uint8_t i = 1; i <= 2; ++i) {
      auto sk =
          dash_pkc::PrivateKey::KeyGen(std::vector<uint8_t>(32, static_cast<uint8_t>(0x30 + i)));
      BOOST_REQUIRE(sk.has_value());
      masterPks.push_back(*sk->GetG1Element(legacy));
      masterSks.push_back(std::move(*sk));
    }

    std::vector<std::vector<uint8_t>> ids;
    std::vector<dash_pkc::G2Element> shareSigs;
    for (uint8_t i = 1; i <= 3; ++i) {
      std::vector<uint8_t> id(32, 0);
      id[0] = i;
      auto skShare = dash_pkc::Threshold::PrivateKeyShare(masterSks, id);
      auto pkShare = dash_pkc::Threshold::PublicKeyShare(masterPks, id);
      BOOST_REQUIRE(skShare.has_value());
      BOOST_REQUIRE(pkShare.has_value());
      BOOST_CHECK(*skShare->GetG1Element(legacy) == *pkShare);

      auto sigShare = skShare->Sign(hash, legacy);
      BOOST_REQUIRE(sigShare.has_value());
      BOOST_CHECK(scheme.Verify(*pkShare, hash, *sigShare));
      if (i <= 2) {
        ids.push_back(id);
        shareSigs.push_back(std::move(*sigShare));
      }
    }

    auto recovered = dash_pkc::Threshold::SignatureRecover(shareSigs, ids);
    BOOST_REQUIRE(recovered.has_value());
    BOOST_CHECK(scheme.Verify(masterPks[0], hash, *recovered));
    BOOST_CHECK(*recovered == *masterSks[0].Sign(hash, legacy));

    auto insufficient = dash_pkc::Threshold::SignatureRecover({shareSigs[0]}, {ids[0]});
    BOOST_CHECK(!insufficient.has_value());
  }
}

// KAT from base-sdk corpus/bls_chia_legacy_threshold.json, generated
// against dashbls / Dash Core. dashbls byte-reverses the sign hash
// (uint256 display order) before signing.
BOOST_AUTO_TEST_CASE(legacy_kat)
{
  auto hash = FromHex("b6d8ee31bbd375dfd55d5fb4b02cfccc68709e64f4c5ffcd3895ceb46540311d");
  std::reverse(hash.begin(), hash.end());
  const auto pkBytes = FromHex(
      "97a12b918eac73718d55b7fca60435ec0b442d7e24b45cbd80f5cf2ea2e14c4164333fffdb00d27e309abbaf"
      "acaa9c34"
  );
  const auto sigBytes = FromHex(
      "031c536960c9c44efefa4a3334d2d1b808f46abe121cd14a1d0b6ee6b6dca85fd3087d86fe5b1327e6792be53f4e"
      "d4"
      "df19c3af3aac79c0bb9dc36fc2a30ba566de6a82cd3e4af2d6654cbe02bb52769a06c1644a4c63b3c3a6fd16e5e6"
      "8e"
      "5c0b"
  );

  auto pk = dash_pkc::G1Element::FromBytes(pkBytes, true);
  auto sig = dash_pkc::G2Element::FromBytes(sigBytes, true);
  BOOST_REQUIRE(pk.has_value());
  BOOST_REQUIRE(sig.has_value());
  BOOST_CHECK(dash_pkc::LegacySchemeMPL().Verify(*pk, hash, *sig));
  BOOST_CHECK(!dash_pkc::BasicSchemeMPL().Verify(*pk, hash, *sig));
}
