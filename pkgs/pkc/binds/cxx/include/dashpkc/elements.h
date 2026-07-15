//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

// G1Element (public keys) and G2Element (signatures) mirroring
// dashbls elements.hpp as consumed by Dash Core.
//
// Deltas vs dashbls: construction goes through FromBytes and always
// validates (no FromBytesUnchecked, no relic interop); failures
// surface as Expected instead of thrown exceptions. A default
// constructed element is null ("reset" in Dash Core terms): it
// serializes as zeros, fails all operations and compares equal only
// to another null element.

#ifndef DASHPKC_ELEMENTS_H
#define DASHPKC_ELEMENTS_H

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>
#include <vector>

#include "dashpkc/expected.h"

namespace dash_pkc::ffi {
class PublicKey;
class Signature;
} // namespace dash_pkc::ffi

namespace dash_pkc {

class G1Element
{
public:
  static constexpr size_t SIZE = 48;

  G1Element() noexcept;
  G1Element(const G1Element& other);
  G1Element(G1Element&&) noexcept;
  G1Element& operator=(const G1Element& other);
  G1Element& operator=(G1Element&&) noexcept;
  ~G1Element();

  bool IsNull() const noexcept;

  static Expected<G1Element> FromBytes(std::span<const uint8_t> bytes, bool fLegacy = false);
  static Expected<G1Element>
  FromByteVector(const std::vector<uint8_t>& bytes, bool fLegacy = false);

  std::array<uint8_t, SIZE> SerializeToArray(bool fLegacy = false) const;
  std::vector<uint8_t> Serialize(bool fLegacy = false) const;

  // True when the element currently holds the legacy (Chia)
  // representation; serialization accepts either flag regardless.
  bool IsLegacy() const;

  friend bool operator==(const G1Element& a, const G1Element& b);
  friend bool operator!=(const G1Element& a, const G1Element& b);

  // Internal: wrap an FFI handle (must be non-null).
  explicit G1Element(std::unique_ptr<ffi::PublicKey> impl) noexcept;
  // Internal: requires !IsNull().
  const ffi::PublicKey& Impl() const;

private:
  std::unique_ptr<ffi::PublicKey> impl_;
};

class G2Element
{
public:
  static constexpr size_t SIZE = 96;

  G2Element() noexcept;
  G2Element(const G2Element& other);
  G2Element(G2Element&&) noexcept;
  G2Element& operator=(const G2Element& other);
  G2Element& operator=(G2Element&&) noexcept;
  ~G2Element();

  bool IsNull() const noexcept;

  static Expected<G2Element> FromBytes(std::span<const uint8_t> bytes, bool fLegacy = false);
  static Expected<G2Element>
  FromByteVector(const std::vector<uint8_t>& bytes, bool fLegacy = false);

  std::array<uint8_t, SIZE> SerializeToArray(bool fLegacy = false) const;
  std::vector<uint8_t> Serialize(bool fLegacy = false) const;

  bool IsLegacy() const;

  // Aggregate subtraction `self + (-other)`, Dash Core's
  // CBLSSignature::SubInsecure (there via operator+ and Negate).
  Expected<G2Element> SubInsecure(const G2Element& other) const;

  friend bool operator==(const G2Element& a, const G2Element& b);
  friend bool operator!=(const G2Element& a, const G2Element& b);

  // Internal: wrap an FFI handle (must be non-null).
  explicit G2Element(std::unique_ptr<ffi::Signature> impl) noexcept;
  // Internal: requires !IsNull().
  const ffi::Signature& Impl() const;

private:
  std::unique_ptr<ffi::Signature> impl_;
};

} // namespace dash_pkc

#endif // DASHPKC_ELEMENTS_H
