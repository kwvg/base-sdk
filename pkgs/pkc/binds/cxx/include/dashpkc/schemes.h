//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

// BasicSchemeMPL / LegacySchemeMPL mirroring the dashbls CoreMPL
// subset Dash Core calls (src/bls/bls.cpp). Unlike dashbls's
// virtual CoreMPL, both schemes share one implementation
// parameterized on the legacy flag; LegacySchemeMPL's unsupported
// overloads simply do not exist here instead of throwing.

#ifndef DASHPKC_SCHEMES_H
#define DASHPKC_SCHEMES_H

#include <cstdint>
#include <span>
#include <vector>

#include "dashpkc/elements.h"
#include "dashpkc/expected.h"
#include "dashpkc/privatekey.h"

namespace dash_pkc {

class CoreMPL
{
public:
  explicit constexpr CoreMPL(bool fLegacy) noexcept
      : fLegacy_(fLegacy)
  {
  }

  Expected<PrivateKey> KeyGen(std::span<const uint8_t> seed) const;
  Expected<G2Element> Sign(const PrivateKey& sk, std::span<const uint8_t> msg) const;
  bool Verify(const G1Element& pk, std::span<const uint8_t> msg, const G2Element& sig) const;

  // Pairwise fast path: no collection handle, no element copies.
  Expected<G1Element> Aggregate(const G1Element& a, const G1Element& b) const;
  Expected<G2Element> Aggregate(const G2Element& a, const G2Element& b) const;

  Expected<G1Element> Aggregate(const std::vector<G1Element>& pks) const;
  Expected<G2Element> Aggregate(const std::vector<G2Element>& sigs) const;

  // Public-key-weighted aggregation of same-message signatures
  // (dashbls CoreMPL::AggregateSecure).
  Expected<G2Element> AggregateSecure(
      const std::vector<G1Element>& pks,
      const std::vector<G2Element>& sigs,
      std::span<const uint8_t> msg
  ) const;

  bool VerifySecure(
      const std::vector<G1Element>& pks, const G2Element& sig, std::span<const uint8_t> msg
  ) const;

  // Aggregate verification over per-signer messages (dashbls
  // CoreMPL::AggregateVerify). Basic enforces distinct messages;
  // legacy does not, matching dashbls.
  bool AggregateVerify(
      const std::vector<G1Element>& pks,
      const std::vector<std::vector<uint8_t>>& msgs,
      const G2Element& sig
  ) const;

  bool IsLegacy() const noexcept
  {
    return fLegacy_;
  }

private:
  bool fLegacy_;
};

class BasicSchemeMPL final : public CoreMPL
{
public:
  constexpr BasicSchemeMPL() noexcept
      : CoreMPL(false)
  {
  }
};

class LegacySchemeMPL final : public CoreMPL
{
public:
  constexpr LegacySchemeMPL() noexcept
      : CoreMPL(true)
  {
  }
};

} // namespace dash_pkc

#endif // DASHPKC_SCHEMES_H
