//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

// Program-lifetime crypto context (libsecp256k1-style): owns all
// runtime caches. The application creates one at init with strong
// entropy and routes hot operations through it.

#ifndef DASH_PKC_SESSION_HPP
#define DASH_PKC_SESSION_HPP

#include <cstdint>
#include <memory>
#include <span>
#include <vector>

#include "dash_pkc/elements.hpp"
#include "dash_pkc/error.hpp"
#include "dash_pkc/ffi/Session.hpp"
#include "dash_pkc/privatekey.hpp"
#include "dash_pkc/schemes.hpp"
#include "dash_pkc/threshold.hpp"

namespace dash_pkc {

// All methods mirror their CoreMPL / Threshold / FromBytes
// equivalents exactly; the session only adds caching. Thread safe.
class Session {
public:
    Session(Session&&) noexcept = default;
    Session& operator=(Session&&) noexcept = default;
    Session(const Session&) = delete;
    Session& operator=(const Session&) = delete;

    // Requires at least 32 bytes of strong entropy (keyed-hash
    // material for content-addressed caches).
    static Expected<Session> Create(std::span<const uint8_t> entropy)
    {
        return detail::WrapPtr<Session>(ffi::Session::create(entropy));
    }

    bool Verify(const G1Element& pk, std::span<const uint8_t> msg, const G2Element& sig, bool fLegacy) const
    {
        if (pk.IsNull() || sig.IsNull()) {
            return false;
        }
        return impl_->verify(sig.Impl(), msg, pk.Impl(), detail::ToScheme(fLegacy)).is_ok();
    }

    bool VerifyAggregated(const std::vector<G1Element>& pks,
                          const std::vector<std::vector<uint8_t>>& msgs,
                          const G2Element& sig,
                          bool fLegacy) const
    {
        const auto vec = detail::MakeVec(pks);
        if (!vec || sig.IsNull()) {
            return false;
        }
        return impl_->verify_aggregated(sig.Impl(), *detail::MakeVec(msgs), *vec, detail::ToScheme(fLegacy)).is_ok();
    }

    bool VerifySecure(const std::vector<G1Element>& pks,
                      const G2Element& sig,
                      std::span<const uint8_t> msg,
                      bool fLegacy) const
    {
        const auto vec = detail::MakeVec(pks);
        if (!vec || sig.IsNull()) {
            return false;
        }
        return impl_->verify_secure(sig.Impl(), *vec, msg, detail::ToScheme(fLegacy)).is_ok();
    }

    Expected<G2Element> AggregateSecure(const std::vector<G1Element>& pks,
                                        const std::vector<G2Element>& sigs,
                                        bool fLegacy) const
    {
        const auto sig_vec = detail::MakeVec(sigs);
        const auto pk_vec = detail::MakeVec(pks);
        if (!sig_vec || !pk_vec) {
            return tl::unexpected(Error::InvalidSignature);
        }
        return detail::WrapPtr<G2Element>(
            impl_->aggregate_secure(*sig_vec, *pk_vec, detail::ToScheme(fLegacy)));
    }

    Expected<G1Element> ParsePublicKey(std::span<const uint8_t> bytes, bool fLegacy) const
    {
        return detail::WrapPtr<G1Element>(impl_->parse_public_key(bytes, detail::ToScheme(fLegacy)));
    }

    Expected<G2Element> ParseSignature(std::span<const uint8_t> bytes, bool fLegacy) const
    {
        return detail::WrapPtr<G2Element>(impl_->parse_signature(bytes, detail::ToScheme(fLegacy)));
    }

    Expected<G1Element> PublicKeyShare(const std::vector<G1Element>& pks, std::span<const uint8_t> id) const
    {
        const auto vec = detail::MakeVec(pks);
        if (!vec) {
            return tl::unexpected(Error::InvalidPublicKey);
        }
        const ffi::Scheme scheme = pks.empty() ? ffi::Scheme(ffi::Scheme::Basic) : pks.front().Impl().scheme();
        return detail::WrapPtr<G1Element>(impl_->public_key_share(*vec, id, scheme));
    }

    Expected<G2Element> SignatureRecover(const std::vector<G2Element>& sigs,
                                         const std::vector<std::vector<uint8_t>>& ids) const
    {
        auto id_vec = ffi::IdVec::new_();
        for (const auto& id : ids) {
            auto pushed = id_vec->push(std::span<const uint8_t>(id.data(), id.size()));
            if (!pushed.is_ok()) {
                return tl::unexpected(FromFfi(*std::move(pushed).err()));
            }
        }
        const auto vec = detail::MakeVec(sigs);
        if (!vec) {
            return tl::unexpected(Error::InvalidSignature);
        }
        const ffi::Scheme scheme = sigs.empty() ? ffi::Scheme(ffi::Scheme::Basic) : sigs.front().Impl().scheme();
        return detail::WrapPtr<G2Element>(impl_->recover_signature(*vec, *id_vec, scheme));
    }

    // Internal: wrap an FFI handle (must be non-null).
    explicit Session(std::unique_ptr<ffi::Session> impl) noexcept : impl_(std::move(impl)) {}
    const ffi::Session& Impl() const { return *impl_; }

private:
    std::unique_ptr<ffi::Session> impl_;
};

} // namespace dash_pkc

#endif // DASH_PKC_SESSION_HPP
