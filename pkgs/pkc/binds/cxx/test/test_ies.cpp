//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

#define BOOST_TEST_MODULE dashpkc_ies
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

BOOST_AUTO_TEST_CASE(single_recipient_round_trip)
{
  auto sk = dash_pkc::PrivateKey::KeyGen(Seq(32, 0x51));
  BOOST_REQUIRE(sk.has_value());
  const auto entropy = Seq(dash_pkc::IES_ENTROPY_SIZE, 0xA0);
  const auto plaintext = Seq(32, 0x61);

  for (const bool legacy : {false, true}) {
    auto pk = sk->GetG1Element(legacy);
    BOOST_REQUIRE(pk.has_value());

    auto blob = dash_pkc::IESBlob::Encrypt(*pk, plaintext, entropy);
    BOOST_REQUIRE(blob.has_value());
    auto plain = blob->Decrypt(*sk, 0, legacy);
    BOOST_REQUIRE(plain.has_value());
    BOOST_CHECK(*plain == plaintext);

    auto reparsed = dash_pkc::IESBlob::FromBytes(blob->Serialize());
    BOOST_REQUIRE(reparsed.has_value());
    auto plain2 = reparsed->Decrypt(*sk, 0, legacy);
    BOOST_REQUIRE(plain2.has_value());
    BOOST_CHECK(*plain2 == plaintext);

    auto other = dash_pkc::PrivateKey::KeyGen(Seq(32, 0x52));
    BOOST_REQUIRE(other.has_value());
    auto wrong = blob->Decrypt(*other, 0, legacy);
    BOOST_CHECK(!wrong.has_value() || *wrong != plaintext);

    BOOST_CHECK(!dash_pkc::IESBlob::Encrypt(*pk, Seq(15, 0), entropy).has_value());
    BOOST_CHECK(!dash_pkc::IESBlob::Encrypt(*pk, plaintext, Seq(32, 0)).has_value());
  }
}

BOOST_AUTO_TEST_CASE(multi_recipient_round_trip)
{
  auto sk1 = dash_pkc::PrivateKey::KeyGen(Seq(32, 0x51));
  auto sk2 = dash_pkc::PrivateKey::KeyGen(Seq(32, 0x53));
  BOOST_REQUIRE(sk1.has_value());
  BOOST_REQUIRE(sk2.has_value());
  const auto entropy = Seq(dash_pkc::IES_ENTROPY_SIZE, 0xA0);

  const std::vector<dash_pkc::G1Element> recipients{
      *sk1->GetG1Element(false), *sk2->GetG1Element(false)
  };
  const std::vector<std::vector<uint8_t>> plaintexts{Seq(16, 0x71), Seq(48, 0x72)};

  auto multi = dash_pkc::IESMultiBlob::Encrypt(recipients, plaintexts, entropy);
  BOOST_REQUIRE(multi.has_value());
  BOOST_CHECK_EQUAL(multi->BlobCount(), 2U);

  auto p0 = multi->Decrypt(0, *sk1);
  auto p1 = multi->Decrypt(1, *sk2);
  BOOST_REQUIRE(p0.has_value());
  BOOST_REQUIRE(p1.has_value());
  BOOST_CHECK(*p0 == plaintexts[0]);
  BOOST_CHECK(*p1 == plaintexts[1]);
  BOOST_CHECK(!multi->Decrypt(2, *sk1).has_value());

  auto reparsed = dash_pkc::IESMultiBlob::FromBytes(multi->Serialize());
  BOOST_REQUIRE(reparsed.has_value());
  auto p0rt = reparsed->Decrypt(0, *sk1);
  BOOST_REQUIRE(p0rt.has_value());
  BOOST_CHECK(*p0rt == plaintexts[0]);
}
