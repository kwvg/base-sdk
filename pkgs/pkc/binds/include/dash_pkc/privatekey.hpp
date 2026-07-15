//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

// PrivateKey mirroring dashbls privatekey.hpp as consumed by
// Dash Core, plus the DHKeyExchange helper.

#ifndef DASH_PKC_PRIVATEKEY_HPP
#define DASH_PKC_PRIVATEKEY_HPP

#include <array>
#include <cstdint>
#include <memory>
#include <span>
#include <vector>

#include "dash_pkc/elements.hpp"
#include "dash_pkc/error.hpp"
#include "dash_pkc/ffi/SecretKey.hpp"
#include "dash_pkc/ffi/SecretKeyVec.hpp"

namespace dash_pkc {

// A BLS12-381 secret scalar. Scheme independent; legacy vs basic is
// chosen per operation, matching Dash Core's usage.
//
// Deltas vs dashbls: parsing rejects the zero scalar outright (no
// IsZero limbo state, no default constructor), the scalar zeroizes
// on drop, and modOrder reduction is not offered (Dash Core always
// passes modOrder=false).
class PrivateKey {
public:
    static constexpr size_t PRIVATE_KEY_SIZE = 32;

    PrivateKey(const PrivateKey& other) : impl_(other.impl_->clone()) {}
    PrivateKey(PrivateKey&&) noexcept = default;
    PrivateKey& operator=(const PrivateKey& other)
    {
        if (this != &other) {
            impl_ = other.impl_->clone();
        }
        return *this;
    }
    PrivateKey& operator=(PrivateKey&&) noexcept = default;

    // Parse a 32-byte big-endian scalar. `modOrder` reduction is
    // unsupported (Error::UnsupportedScheme) by design.
    static Expected<PrivateKey> FromBytes(std::span<const uint8_t> bytes, bool modOrder = false)
    {
        if (modOrder) {
            return tl::unexpected(Error::UnsupportedScheme);
        }
        return detail::WrapPtr<PrivateKey>(ffi::SecretKey::from_bytes(bytes));
    }

    static Expected<PrivateKey> FromByteVector(const std::vector<uint8_t>& bytes, bool modOrder = false)
    {
        return FromBytes(std::span<const uint8_t>(bytes.data(), bytes.size()), modOrder);
    }

    // Derive a key from >= 32 bytes of seed material (dashbls
    // EIP-2333 v3 KeyGen, i.e. HDKeys::KeyGen).
    static Expected<PrivateKey> KeyGen(std::span<const uint8_t> seed)
    {
        return detail::WrapPtr<PrivateKey>(ffi::SecretKey::generate(seed));
    }

    // Sum keys mod the group order (dashbls PrivateKey::Aggregate).
    static Expected<PrivateKey> Aggregate(const std::vector<PrivateKey>& keys)
    {
        auto vec = ffi::SecretKeyVec::new_();
        for (const auto& key : keys) {
            vec->push(key.Impl());
        }
        return detail::WrapPtr<PrivateKey>(ffi::SecretKey::aggregate(*vec));
    }

    Expected<G1Element> GetG1Element(bool fLegacy = false) const
    {
        return detail::WrapPtr<G1Element>(impl_->public_key(detail::ToScheme(fLegacy)));
    }

    // Sign under the requested scheme; legacy signing requires a
    // 32-byte message (a hash), matching dashbls.
    Expected<G2Element> Sign(std::span<const uint8_t> msg, bool fLegacy = false) const
    {
        return detail::WrapPtr<G2Element>(impl_->sign(msg, detail::ToScheme(fLegacy)));
    }

    // The caller owns wiping the returned secret bytes.
    std::array<uint8_t, PRIVATE_KEY_SIZE> SerializeToArray() const
    {
        std::array<uint8_t, PRIVATE_KEY_SIZE> out{};
        (void)impl_->to_bytes(std::span<uint8_t>(out.data(), out.size()));
        return out;
    }

    std::vector<uint8_t> Serialize(bool fLegacy = false) const
    {
        (void)fLegacy; // secret scalars are scheme invariant, as in dashbls
        const auto arr = SerializeToArray();
        return std::vector<uint8_t>(arr.begin(), arr.end());
    }

    // Constant-time comparison.
    friend bool operator==(const PrivateKey& a, const PrivateKey& b) { return a.impl_->eq(*b.impl_); }
    friend bool operator!=(const PrivateKey& a, const PrivateKey& b) { return !(a == b); }

    // Internal: wrap an FFI handle (must be non-null).
    explicit PrivateKey(std::unique_ptr<ffi::SecretKey> impl) noexcept : impl_(std::move(impl)) {}
    const ffi::SecretKey& Impl() const { return *impl_; }

private:
    std::unique_ptr<ffi::SecretKey> impl_;
};

// Diffie-Hellman exchange `sk * pk` (Dash Core's DHKeyExchange,
// there via operator* on PrivateKey and G1Element). The result
// carries the peer key's scheme tag.
inline Expected<G1Element> DHKeyExchange(const PrivateKey& sk, const G1Element& pk)
{
    return detail::WrapPtr<G1Element>(sk.Impl().dh_exchange(pk.Impl()));
}

} // namespace dash_pkc

#endif // DASH_PKC_PRIVATEKEY_HPP
