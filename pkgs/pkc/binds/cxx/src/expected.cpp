//
// Copyright (c) 2026-present, The Dash Core developers
// SPDX-License-Identifier: MIT
// See the accompanying file LICENSE or https://opensource.org/license/MIT
//

#include "dashpkc/expected.h"

#include "detail.h"

namespace dash_pkc {

// The public enum must mirror the generated FFI enum exactly; the
// implementation is the only place both are visible.
static_assert(static_cast<int32_t>(Error::InvalidKeyMaterial) == ffi::PkcError::InvalidKeyMaterial);
static_assert(static_cast<int32_t>(Error::VerifyFailed) == ffi::PkcError::VerifyFailed);
static_assert(static_cast<int32_t>(Error::UnsupportedScheme) == ffi::PkcError::UnsupportedScheme);
static_assert(static_cast<int32_t>(Error::InternalError) == ffi::PkcError::InternalError);

const char* ErrorName(Error err) noexcept
{
  switch (err) {
  case Error::InvalidKeyMaterial:
    return "invalid key material";
  case Error::InvalidSecretKey:
    return "invalid secret key";
  case Error::InvalidPublicKey:
    return "invalid public key";
  case Error::InvalidSignature:
    return "invalid signature";
  case Error::VerifyFailed:
    return "verification failed";
  case Error::InvalidMessageLength:
    return "invalid message length";
  case Error::EmptyAggregation:
    return "empty aggregation";
  case Error::CountMismatch:
    return "count mismatch";
  case Error::ThresholdTooLarge:
    return "threshold too large";
  case Error::InsufficientShares:
    return "insufficient shares";
  case Error::DuplicateShareId:
    return "duplicate share id";
  case Error::InvalidShareId:
    return "invalid share id";
  case Error::InvalidVerificationVector:
    return "invalid verification vector";
  case Error::DuplicateMessage:
    return "duplicate message";
  case Error::ShareIdMismatch:
    return "share id mismatch";
  case Error::InvalidPlaintextLength:
    return "invalid plaintext length";
  case Error::DecryptionFailed:
    return "decryption failed";
  case Error::IndexOutOfRange:
    return "index out of range";
  case Error::UnsupportedScheme:
    return "unsupported scheme";
  case Error::InvalidLength:
    return "invalid length";
  case Error::InvalidEncoding:
    return "invalid encoding";
  case Error::InsufficientEntropy:
    return "insufficient entropy";
  case Error::InternalError:
    return "internal error";
  }
  return "unknown error";
}

} // namespace dash_pkc
