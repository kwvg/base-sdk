//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

// G1Element (public keys) and G2Element (signatures) mirroring
// dashbls elements.hpp as consumed by Dash Core.

#ifndef DASH_PKC_ELEMENTS_HPP
#define DASH_PKC_ELEMENTS_HPP

#include <array>
#include <cstdint>
#include <memory>
#include <span>
#include <vector>

#include "dash_pkc/error.hpp"
#include "dash_pkc/ffi/PublicKey.hpp"
#include "dash_pkc/ffi/Signature.hpp"

namespace dash_pkc {

// A validated G1 group element (BLS public key).
//
// Deltas vs dashbls: construction goes through FromBytes and always
// validates (no FromBytesUnchecked, no infinity default constructor,
// no relic interop); failures surface as Expected instead of thrown
// exceptions.
class G1Element {
public:
    static constexpr size_t SIZE = 48;

    G1Element(const G1Element& other) : impl_(other.impl_->clone()) {}
    G1Element(G1Element&&) noexcept = default;
    G1Element& operator=(const G1Element& other)
    {
        if (this != &other) {
            impl_ = other.impl_->clone();
        }
        return *this;
    }
    G1Element& operator=(G1Element&&) noexcept = default;

    static Expected<G1Element> FromBytes(std::span<const uint8_t> bytes, bool fLegacy = false)
    {
        return detail::WrapPtr<G1Element>(ffi::PublicKey::from_bytes(bytes, detail::ToScheme(fLegacy)));
    }

    static Expected<G1Element> FromByteVector(const std::vector<uint8_t>& bytes, bool fLegacy = false)
    {
        return FromBytes(std::span<const uint8_t>(bytes.data(), bytes.size()), fLegacy);
    }

    // Serialization mirrors dashbls (compressed, legacy or basic
    // flag bits). Internal conversion failure cannot occur for a
    // validated element; if it ever did, the zero-filled buffer is
    // returned, matching Dash Core's invalid-object serialization.
    std::array<uint8_t, SIZE> SerializeToArray(bool fLegacy = false) const
    {
        std::array<uint8_t, SIZE> out{};
        (void)impl_->to_bytes(std::span<uint8_t>(out.data(), out.size()), detail::ToScheme(fLegacy));
        return out;
    }

    std::vector<uint8_t> Serialize(bool fLegacy = false) const
    {
        const auto arr = SerializeToArray(fLegacy);
        return std::vector<uint8_t>(arr.begin(), arr.end());
    }

    // True when the element currently holds the legacy (Chia)
    // representation; serialization accepts either flag regardless.
    bool IsLegacy() const { return impl_->scheme() == ffi::Scheme::Legacy; }

    friend bool operator==(const G1Element& a, const G1Element& b) { return a.impl_->eq(*b.impl_); }
    friend bool operator!=(const G1Element& a, const G1Element& b) { return !(a == b); }

    // Internal: wrap an FFI handle (must be non-null).
    explicit G1Element(std::unique_ptr<ffi::PublicKey> impl) noexcept : impl_(std::move(impl)) {}
    const ffi::PublicKey& Impl() const { return *impl_; }

private:
    std::unique_ptr<ffi::PublicKey> impl_;
};

// A validated G2 group element (BLS signature). Same deltas vs
// dashbls as G1Element.
class G2Element {
public:
    static constexpr size_t SIZE = 96;

    G2Element(const G2Element& other) : impl_(other.impl_->clone()) {}
    G2Element(G2Element&&) noexcept = default;
    G2Element& operator=(const G2Element& other)
    {
        if (this != &other) {
            impl_ = other.impl_->clone();
        }
        return *this;
    }
    G2Element& operator=(G2Element&&) noexcept = default;

    static Expected<G2Element> FromBytes(std::span<const uint8_t> bytes, bool fLegacy = false)
    {
        return detail::WrapPtr<G2Element>(ffi::Signature::from_bytes(bytes, detail::ToScheme(fLegacy)));
    }

    static Expected<G2Element> FromByteVector(const std::vector<uint8_t>& bytes, bool fLegacy = false)
    {
        return FromBytes(std::span<const uint8_t>(bytes.data(), bytes.size()), fLegacy);
    }

    std::array<uint8_t, SIZE> SerializeToArray(bool fLegacy = false) const
    {
        std::array<uint8_t, SIZE> out{};
        (void)impl_->to_bytes(std::span<uint8_t>(out.data(), out.size()), detail::ToScheme(fLegacy));
        return out;
    }

    std::vector<uint8_t> Serialize(bool fLegacy = false) const
    {
        const auto arr = SerializeToArray(fLegacy);
        return std::vector<uint8_t>(arr.begin(), arr.end());
    }

    bool IsLegacy() const { return impl_->scheme() == ffi::Scheme::Legacy; }

    // Aggregate subtraction `self + (-other)`, Dash Core's
    // CBLSSignature::SubInsecure (there via operator+ and Negate).
    Expected<G2Element> SubInsecure(const G2Element& other) const
    {
        return detail::WrapPtr<G2Element>(impl_->sub_insecure(*other.impl_));
    }

    friend bool operator==(const G2Element& a, const G2Element& b) { return a.impl_->eq(*b.impl_); }
    friend bool operator!=(const G2Element& a, const G2Element& b) { return !(a == b); }

    // Internal: wrap an FFI handle (must be non-null).
    explicit G2Element(std::unique_ptr<ffi::Signature> impl) noexcept : impl_(std::move(impl)) {}
    const ffi::Signature& Impl() const { return *impl_; }

private:
    std::unique_ptr<ffi::Signature> impl_;
};

} // namespace dash_pkc

#endif // DASH_PKC_ELEMENTS_HPP
