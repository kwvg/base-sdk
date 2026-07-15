//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

// Error type and tl::expected plumbing shared by all wrappers.

#ifndef DASH_PKC_ERROR_HPP
#define DASH_PKC_ERROR_HPP

#include <cstdint>
#include <memory>
#include <utility>

#include <tl/expected.hpp>

#include "dash_pkc/ffi/PkcError.hpp"
#include "dash_pkc/ffi/Scheme.hpp"

namespace dash_pkc {

// Mirrors dash_pkc::ffi::PkcError (same order and values), which in
// turn mirrors dash_pkc::bls::BlsError plus FFI-boundary failures.
enum class Error : int32_t {
  InvalidKeyMaterial = ffi::PkcError::InvalidKeyMaterial,
  InvalidSecretKey = ffi::PkcError::InvalidSecretKey,
  InvalidPublicKey = ffi::PkcError::InvalidPublicKey,
  InvalidSignature = ffi::PkcError::InvalidSignature,
  VerifyFailed = ffi::PkcError::VerifyFailed,
  InvalidMessageLength = ffi::PkcError::InvalidMessageLength,
  EmptyAggregation = ffi::PkcError::EmptyAggregation,
  CountMismatch = ffi::PkcError::CountMismatch,
  ThresholdTooLarge = ffi::PkcError::ThresholdTooLarge,
  InsufficientShares = ffi::PkcError::InsufficientShares,
  DuplicateShareId = ffi::PkcError::DuplicateShareId,
  InvalidShareId = ffi::PkcError::InvalidShareId,
  InvalidVerificationVector = ffi::PkcError::InvalidVerificationVector,
  DuplicateMessage = ffi::PkcError::DuplicateMessage,
  ShareIdMismatch = ffi::PkcError::ShareIdMismatch,
  InvalidPlaintextLength = ffi::PkcError::InvalidPlaintextLength,
  DecryptionFailed = ffi::PkcError::DecryptionFailed,
  IndexOutOfRange = ffi::PkcError::IndexOutOfRange,
  UnsupportedScheme = ffi::PkcError::UnsupportedScheme,
  InvalidLength = ffi::PkcError::InvalidLength,
  InvalidEncoding = ffi::PkcError::InvalidEncoding,
  InsufficientEntropy = ffi::PkcError::InsufficientEntropy,
  InternalError = ffi::PkcError::InternalError,
};

// Result carrier preserving dash-pkc's Result<T, E> semantics; this
// library never throws.
template <typename T>
using Expected = tl::expected<T, Error>;

constexpr Error FromFfi(ffi::PkcError err) noexcept
{
    return static_cast<Error>(static_cast<ffi::PkcError::Value>(err));
}

constexpr const char* ErrorName(Error err) noexcept
{
    switch (err) {
    case Error::InvalidKeyMaterial: return "invalid key material";
    case Error::InvalidSecretKey: return "invalid secret key";
    case Error::InvalidPublicKey: return "invalid public key";
    case Error::InvalidSignature: return "invalid signature";
    case Error::VerifyFailed: return "verification failed";
    case Error::InvalidMessageLength: return "invalid message length";
    case Error::EmptyAggregation: return "empty aggregation";
    case Error::CountMismatch: return "count mismatch";
    case Error::ThresholdTooLarge: return "threshold too large";
    case Error::InsufficientShares: return "insufficient shares";
    case Error::DuplicateShareId: return "duplicate share id";
    case Error::InvalidShareId: return "invalid share id";
    case Error::InvalidVerificationVector: return "invalid verification vector";
    case Error::DuplicateMessage: return "duplicate message";
    case Error::ShareIdMismatch: return "share id mismatch";
    case Error::InvalidPlaintextLength: return "invalid plaintext length";
    case Error::DecryptionFailed: return "decryption failed";
    case Error::IndexOutOfRange: return "index out of range";
    case Error::UnsupportedScheme: return "unsupported scheme";
    case Error::InvalidLength: return "invalid length";
    case Error::InvalidEncoding: return "invalid encoding";
    case Error::InsufficientEntropy: return "insufficient entropy";
    case Error::InternalError: return "internal error";
    }
    return "unknown error";
}

namespace detail {

constexpr ffi::Scheme ToScheme(bool fLegacy) noexcept
{
    return fLegacy ? ffi::Scheme::Legacy : ffi::Scheme::Basic;
}

// Unwrap a diplomat pointer result into a wrapper type constructed
// from the unique_ptr.
template <typename Wrapper, typename FfiT>
inline Expected<Wrapper> WrapPtr(diplomat::result<std::unique_ptr<FfiT>, ffi::PkcError>&& res)
{
    if (res.is_ok()) {
        return Wrapper(std::move(*std::move(res).ok()));
    }
    return tl::unexpected(FromFfi(*std::move(res).err()));
}

inline Expected<void> WrapVoid(diplomat::result<std::monostate, ffi::PkcError>&& res)
{
    if (res.is_ok()) {
        return {};
    }
    return tl::unexpected(FromFfi(*std::move(res).err()));
}

} // namespace detail

} // namespace dash_pkc

#endif // DASH_PKC_ERROR_HPP
