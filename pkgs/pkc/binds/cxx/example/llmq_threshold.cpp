//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

// LLMQ-shaped threshold signing walkthrough: a dealer polynomial
// (the master secret keys) is evaluated at each member's id to hand
// out secret key shares; a threshold of members sign the same sign
// hash; their shares recover the quorum signature, which verifies
// against the quorum public key. A Session provides the runtime
// caches a long-lived process would use.

#include <cstdio>
#include <cstdlib>
#include <vector>

#include <dashpkc/dashpkc.h>

int main()
{
  constexpr size_t kMembers = 5;
  constexpr size_t kThreshold = 3;
  const bool legacy = false; // basic scheme, as post-v19 mainnet

  std::vector<uint8_t> entropy(32);
  for (size_t i = 0; i < entropy.size(); ++i) {
    entropy[i] = static_cast<uint8_t>(0xC0 + i);
  }
  auto session = dash_pkc::Session::Create(entropy);
  if (!session.has_value()) {
    return EXIT_FAILURE;
  }

  // Dealer: threshold-many random master keys form the polynomial;
  // index 0 is the quorum secret key.
  std::vector<dash_pkc::PrivateKey> masterSks;
  std::vector<dash_pkc::G1Element> masterPks;
  for (size_t i = 0; i < kThreshold; ++i) {
    auto sk = dash_pkc::PrivateKey::KeyGen(std::vector<uint8_t>(32, static_cast<uint8_t>(i + 1)));
    if (!sk.has_value()) {
      return EXIT_FAILURE;
    }
    masterPks.push_back(*sk->GetG1Element(legacy));
    masterSks.push_back(std::move(*sk));
  }
  const dash_pkc::G1Element quorumPk = masterPks[0];

  // Members: share = polynomial evaluated at the member id.
  std::vector<std::vector<uint8_t>> memberIds;
  std::vector<dash_pkc::PrivateKey> memberShares;
  for (size_t i = 0; i < kMembers; ++i) {
    std::vector<uint8_t> id(32, 0);
    id[0] = static_cast<uint8_t>(i + 1);
    auto share = dash_pkc::Threshold::PrivateKeyShare(masterSks, id);
    auto pkShare = session->PublicKeyShare(masterPks, id);
    if (!share.has_value() || !pkShare.has_value()) {
      return EXIT_FAILURE;
    }
    if (*share->GetG1Element(legacy) != *pkShare) {
      std::fprintf(stderr, "member %zu: share does not match verification vector\n", i);
      return EXIT_FAILURE;
    }
    memberIds.push_back(std::move(id));
    memberShares.push_back(std::move(*share));
  }

  // Signing session: any threshold-many members sign the hash.
  const std::vector<uint8_t> signHash(32, 0x99);
  std::vector<dash_pkc::G2Element> sigShares;
  std::vector<std::vector<uint8_t>> signerIds;
  for (size_t i = 0; i < kThreshold; ++i) {
    auto sigShare = memberShares[i].Sign(signHash, legacy);
    if (!sigShare.has_value()) {
      return EXIT_FAILURE;
    }
    sigShares.push_back(std::move(*sigShare));
    signerIds.push_back(memberIds[i]);
  }

  auto recovered = session->SignatureRecover(sigShares, signerIds);
  if (!recovered.has_value()) {
    std::fprintf(stderr, "recover: %s\n", dash_pkc::ErrorName(recovered.error()));
    return EXIT_FAILURE;
  }

  if (!session->Verify(quorumPk, signHash, *recovered, legacy)) {
    std::fprintf(stderr, "recovered signature does not verify\n");
    return EXIT_FAILURE;
  }

  std::printf(
      "quorum %zu-of-%zu: recovered signature verifies against the quorum key\n",
      kThreshold,
      kMembers
  );
  return EXIT_SUCCESS;
}
