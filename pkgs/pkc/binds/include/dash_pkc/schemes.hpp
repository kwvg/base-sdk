//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

// BasicSchemeMPL / LegacySchemeMPL mirroring the dashbls CoreMPL
// subset Dash Core calls (src/bls/bls.cpp).

#ifndef DASH_PKC_SCHEMES_HPP
#define DASH_PKC_SCHEMES_HPP

#include <cstdint>
#include <memory>
#include <span>
#include <vector>

#include "dash_pkc/elements.hpp"
#include "dash_pkc/error.hpp"
#include "dash_pkc/ffi/MessageVec.hpp"
#include "dash_pkc/ffi/PublicKeyVec.hpp"
#include "dash_pkc/ffi/SignatureVec.hpp"
#include "dash_pkc/privatekey.hpp"

namespace dash_pkc {

namespace detail {

// Null elements yield a null vec; callers translate that to an
// error instead of dereferencing a null handle.
inline std::unique_ptr<ffi::PublicKeyVec> MakeVec(const std::vector<G1Element>& pks)
{
    auto vec = ffi::PublicKeyVec::new_();
    for (const auto& pk : pks) {
        if (pk.IsNull()) {
            return nullptr;
        }
        vec->push(pk.Impl());
    }
    return vec;
}

inline std::unique_ptr<ffi::SignatureVec> MakeVec(const std::vector<G2Element>& sigs)
{
    auto vec = ffi::SignatureVec::new_();
    for (const auto& sig : sigs) {
        if (sig.IsNull()) {
            return nullptr;
        }
        vec->push(sig.Impl());
    }
    return vec;
}

inline std::unique_ptr<ffi::MessageVec> MakeVec(const std::vector<std::vector<uint8_t>>& msgs)
{
    auto vec = ffi::MessageVec::new_();
    for (const auto& msg : msgs) {
        vec->push(std::span<const uint8_t>(msg.data(), msg.size()));
    }
    return vec;
}

} // namespace detail

// Concrete scheme facade. Unlike dashbls's virtual CoreMPL, both
// schemes share this one implementation parameterized on the flag;
// LegacySchemeMPL's unsupported overloads simply do not exist here
// instead of throwing.
class CoreMPL {
public:
    explicit constexpr CoreMPL(bool fLegacy) noexcept : fLegacy_(fLegacy) {}

    Expected<PrivateKey> KeyGen(std::span<const uint8_t> seed) const { return PrivateKey::KeyGen(seed); }

    Expected<G2Element> Sign(const PrivateKey& sk, std::span<const uint8_t> msg) const
    {
        return sk.Sign(msg, fLegacy_);
    }

    bool Verify(const G1Element& pk, std::span<const uint8_t> msg, const G2Element& sig) const
    {
        if (pk.IsNull() || sig.IsNull()) {
            return false;
        }
        return sig.Impl().verify(msg, pk.Impl(), detail::ToScheme(fLegacy_)).is_ok();
    }

    Expected<G1Element> Aggregate(const std::vector<G1Element>& pks) const
    {
        const auto vec = detail::MakeVec(pks);
        if (!vec) {
            return tl::unexpected(Error::InvalidPublicKey);
        }
        return detail::WrapPtr<G1Element>(ffi::PublicKey::aggregate(*vec, detail::ToScheme(fLegacy_)));
    }

    Expected<G2Element> Aggregate(const std::vector<G2Element>& sigs) const
    {
        const auto vec = detail::MakeVec(sigs);
        if (!vec) {
            return tl::unexpected(Error::InvalidSignature);
        }
        return detail::WrapPtr<G2Element>(ffi::Signature::aggregate(*vec, detail::ToScheme(fLegacy_)));
    }

    // Public-key-weighted aggregation of same-message signatures
    // (dashbls CoreMPL::AggregateSecure).
    Expected<G2Element> AggregateSecure(const std::vector<G1Element>& pks,
                                        const std::vector<G2Element>& sigs,
                                        std::span<const uint8_t> msg) const
    {
        (void)msg; // weights depend only on the sorted public keys
        const auto sig_vec = detail::MakeVec(sigs);
        const auto pk_vec = detail::MakeVec(pks);
        if (!sig_vec || !pk_vec) {
            return tl::unexpected(Error::InvalidSignature);
        }
        return detail::WrapPtr<G2Element>(
            ffi::Signature::aggregate_secure(*sig_vec, *pk_vec, detail::ToScheme(fLegacy_)));
    }

    bool VerifySecure(const std::vector<G1Element>& pks, const G2Element& sig, std::span<const uint8_t> msg) const
    {
        const auto vec = detail::MakeVec(pks);
        if (!vec || sig.IsNull()) {
            return false;
        }
        return sig.Impl().verify_secure(*vec, msg, detail::ToScheme(fLegacy_)).is_ok();
    }

    // Aggregate verification over per-signer messages (dashbls
    // CoreMPL::AggregateVerify). Basic enforces distinct messages;
    // legacy does not, matching dashbls.
    bool AggregateVerify(const std::vector<G1Element>& pks,
                         const std::vector<std::vector<uint8_t>>& msgs,
                         const G2Element& sig) const
    {
        const auto vec = detail::MakeVec(pks);
        if (!vec || sig.IsNull()) {
            return false;
        }
        return sig.Impl().verify_aggregated(*detail::MakeVec(msgs), *vec, detail::ToScheme(fLegacy_)).is_ok();
    }

    bool IsLegacy() const noexcept { return fLegacy_; }

private:
    bool fLegacy_;
};

class BasicSchemeMPL final : public CoreMPL {
public:
    constexpr BasicSchemeMPL() noexcept : CoreMPL(false) {}
};

class LegacySchemeMPL final : public CoreMPL {
public:
    constexpr LegacySchemeMPL() noexcept : CoreMPL(true) {}
};

} // namespace dash_pkc

#endif // DASH_PKC_SCHEMES_HPP
