//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

// Program-lifetime crypto context (libsecp256k1-style): owns all
// runtime caches (hash-to-G2 message points, validated parses,
// weighted quorum keys, Lagrange coefficients, verification
// results). The application creates one at init with strong
// entropy and routes hot operations through it; every method
// mirrors its CoreMPL / Threshold / FromBytes equivalent exactly,
// the session only adds caching. Thread safe.

#ifndef DASHPKC_SESSION_H
#define DASHPKC_SESSION_H

#include <cstdint>
#include <memory>
#include <span>
#include <vector>

#include "dashpkc/elements.h"
#include "dashpkc/expected.h"
#include "dashpkc/privatekey.h"

namespace dash_pkc::ffi {
class Session;
} // namespace dash_pkc::ffi

namespace dash_pkc {

class Session
{
public:
  Session(Session&&) noexcept;
  Session& operator=(Session&&) noexcept;
  Session(const Session&) = delete;
  Session& operator=(const Session&) = delete;
  ~Session();

  // Requires at least 32 bytes of strong entropy (keyed-hash
  // material for content-addressed caches).
  static Expected<Session> Create(std::span<const uint8_t> entropy);

  bool Verify(
      const G1Element& pk, std::span<const uint8_t> msg, const G2Element& sig, bool fLegacy
  ) const;

  bool VerifyAggregated(
      const std::vector<G1Element>& pks,
      const std::vector<std::vector<uint8_t>>& msgs,
      const G2Element& sig,
      bool fLegacy
  ) const;

  bool VerifySecure(
      const std::vector<G1Element>& pks,
      const G2Element& sig,
      std::span<const uint8_t> msg,
      bool fLegacy
  ) const;

  Expected<G2Element> AggregateSecure(
      const std::vector<G1Element>& pks, const std::vector<G2Element>& sigs, bool fLegacy
  ) const;

  Expected<G1Element> ParsePublicKey(std::span<const uint8_t> bytes, bool fLegacy) const;
  Expected<G2Element> ParseSignature(std::span<const uint8_t> bytes, bool fLegacy) const;

  Expected<G1Element>
  PublicKeyShare(const std::vector<G1Element>& pks, std::span<const uint8_t> id) const;

  Expected<G2Element> SignatureRecover(
      const std::vector<G2Element>& sigs, const std::vector<std::vector<uint8_t>>& ids
  ) const;

  // Internal: wrap an FFI handle (must be non-null).
  explicit Session(std::unique_ptr<ffi::Session> impl) noexcept;
  const ffi::Session& Impl() const;

private:
  std::unique_ptr<ffi::Session> impl_;
};

} // namespace dash_pkc

#endif // DASHPKC_SESSION_H
