//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

// Error type and Result carrier for the dashpkc API. This library
// never throws: every fallible operation returns Expected<T>.

#ifndef DASHPKC_EXPECTED_H
#define DASHPKC_EXPECTED_H

#include <cstdint>

#include "dashpkc/vendor/tl_unexpected.hpp"

namespace dash_pkc {

// Mirrors dash_pkc::ffi::PkcError (validated by static_asserts in
// the implementation), which in turn mirrors the Rust BlsError
// plus FFI-boundary failures.
enum class Error : int32_t {
  InvalidKeyMaterial = 0,
  InvalidSecretKey,
  InvalidPublicKey,
  InvalidSignature,
  VerifyFailed,
  InvalidMessageLength,
  EmptyAggregation,
  CountMismatch,
  ThresholdTooLarge,
  InsufficientShares,
  DuplicateShareId,
  InvalidShareId,
  InvalidVerificationVector,
  DuplicateMessage,
  ShareIdMismatch,
  InvalidPlaintextLength,
  DecryptionFailed,
  IndexOutOfRange,
  UnsupportedScheme,
  InvalidLength,
  InvalidEncoding,
  InsufficientEntropy,
  InternalError,
};

const char* ErrorName(Error err) noexcept;

template <typename T>
using Expected = tl::expected<T, Error>;

} // namespace dash_pkc

#endif // DASHPKC_EXPECTED_H
