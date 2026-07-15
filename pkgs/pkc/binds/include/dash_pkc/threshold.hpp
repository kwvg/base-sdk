//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

// The bls::Threshold subset Dash Core calls: PrivateKeyShare,
// PublicKeyShare and SignatureRecover.

#ifndef DASH_PKC_THRESHOLD_HPP
#define DASH_PKC_THRESHOLD_HPP

#include <cstdint>
#include <memory>
#include <span>
#include <vector>

#include "dash_pkc/elements.hpp"
#include "dash_pkc/error.hpp"
#include "dash_pkc/ffi/IdVec.hpp"
#include "dash_pkc/ffi/SecretKeyVec.hpp"
#include "dash_pkc/privatekey.hpp"
#include "dash_pkc/schemes.hpp"

namespace dash_pkc::Threshold {

// Evaluate the secret polynomial `sks` at the 32-byte participant
// `id` (dashbls Threshold::PrivateKeyShare).
inline Expected<PrivateKey> PrivateKeyShare(const std::vector<PrivateKey>& sks, std::span<const uint8_t> id)
{
    auto vec = ffi::SecretKeyVec::new_();
    for (const auto& sk : sks) {
        if (sk.IsNull()) {
            return tl::unexpected(Error::InvalidSecretKey);
        }
        vec->push(sk.Impl());
    }
    return detail::WrapPtr<PrivateKey>(ffi::SecretKey::derive_share(*vec, id));
}

// Evaluate the public polynomial `pks` at the 32-byte participant
// `id` (dashbls Threshold::PublicKeyShare).
inline Expected<G1Element> PublicKeyShare(const std::vector<G1Element>& pks, std::span<const uint8_t> id)
{
    const auto vec = detail::MakeVec(pks);
    if (!vec) {
        return tl::unexpected(Error::InvalidPublicKey);
    }
    const ffi::Scheme scheme = pks.empty() ? ffi::Scheme(ffi::Scheme::Basic) : pks.front().Impl().scheme();
    return detail::WrapPtr<G1Element>(ffi::PublicKey::derive_share(*vec, id, scheme));
}

// Recover a threshold signature from shares and their 32-byte ids
// via Lagrange interpolation (dashbls Threshold::SignatureRecover).
inline Expected<G2Element> SignatureRecover(const std::vector<G2Element>& sigs,
                                            const std::vector<std::vector<uint8_t>>& ids)
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
    return detail::WrapPtr<G2Element>(ffi::Signature::recover(*vec, *id_vec, scheme));
}

} // namespace dash_pkc::Threshold

#endif // DASH_PKC_THRESHOLD_HPP
