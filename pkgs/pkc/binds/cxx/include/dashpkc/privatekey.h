//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

// PrivateKey mirroring dashbls privatekey.hpp as consumed by
// Dash Core, plus the DHKeyExchange helper.
//
// Deltas vs dashbls: parsing rejects the zero scalar outright, the
// scalar zeroizes on drop, and modOrder reduction is accepted but
// ignored (out-of-range scalars are always rejected). A default
// constructed key is null: it serializes as zeros and fails all
// operations.

#ifndef DASHPKC_PRIVATEKEY_H
#define DASHPKC_PRIVATEKEY_H

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>
#include <vector>

#include "dashpkc/elements.h"
#include "dashpkc/expected.h"

namespace dash_pkc::ffi {
class SecretKey;
} // namespace dash_pkc::ffi

namespace dash_pkc {

class PrivateKey
{
public:
  static constexpr size_t PRIVATE_KEY_SIZE = 32;

  PrivateKey() noexcept;
  PrivateKey(const PrivateKey& other);
  PrivateKey(PrivateKey&&) noexcept;
  PrivateKey& operator=(const PrivateKey& other);
  PrivateKey& operator=(PrivateKey&&) noexcept;
  ~PrivateKey();

  bool IsNull() const noexcept;

  static Expected<PrivateKey> FromBytes(std::span<const uint8_t> bytes, bool modOrder = false);
  static Expected<PrivateKey>
  FromByteVector(const std::vector<uint8_t>& bytes, bool modOrder = false);

  // Derive a key from >= 32 bytes of seed material (dashbls
  // EIP-2333 v3 KeyGen, i.e. HDKeys::KeyGen).
  static Expected<PrivateKey> KeyGen(std::span<const uint8_t> seed);

  // Sum keys mod the group order (dashbls PrivateKey::Aggregate).
  static Expected<PrivateKey> Aggregate(const std::vector<PrivateKey>& keys);

  Expected<G1Element> GetG1Element(bool fLegacy = false) const;

  // Sign under the requested scheme; legacy signing requires a
  // 32-byte message (a hash), matching dashbls.
  Expected<G2Element> Sign(std::span<const uint8_t> msg, bool fLegacy = false) const;

  // The caller owns wiping the returned secret bytes. Secret
  // scalars are scheme invariant; the flag overloads exist for
  // generic wrappers that pass one.
  std::array<uint8_t, PRIVATE_KEY_SIZE> SerializeToArray() const;
  std::array<uint8_t, PRIVATE_KEY_SIZE> SerializeToArray(bool fLegacy) const;
  std::vector<uint8_t> Serialize(bool fLegacy = false) const;

  // Constant-time comparison (null keys compare equal to null).
  friend bool operator==(const PrivateKey& a, const PrivateKey& b);
  friend bool operator!=(const PrivateKey& a, const PrivateKey& b);

  // Internal: wrap an FFI handle (must be non-null).
  explicit PrivateKey(std::unique_ptr<ffi::SecretKey> impl) noexcept;
  // Internal: requires !IsNull().
  const ffi::SecretKey& Impl() const;

private:
  std::unique_ptr<ffi::SecretKey> impl_;
};

// Diffie-Hellman exchange `sk * pk` (Dash Core's DHKeyExchange,
// there via operator* on PrivateKey and G1Element). The result
// carries the peer key's scheme tag.
Expected<G1Element> DHKeyExchange(const PrivateKey& sk, const G1Element& pk);

} // namespace dash_pkc

#endif // DASHPKC_PRIVATEKEY_H
