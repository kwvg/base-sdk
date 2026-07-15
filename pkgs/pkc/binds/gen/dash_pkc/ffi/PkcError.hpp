#ifndef dash_pkc_ffi_PkcError_HPP
#define dash_pkc_ffi_PkcError_HPP

#include "PkcError.d.hpp"

#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <memory>
#include <functional>
#include <optional>
#include <cstdlib>
#include "../../diplomat_runtime.hpp"


namespace dash_pkc::ffi {
namespace capi {

} // namespace capi
} // namespace

inline dash_pkc::ffi::capi::PkcError dash_pkc::ffi::PkcError::AsFFI() const {
    return static_cast<dash_pkc::ffi::capi::PkcError>(value);
}

inline dash_pkc::ffi::PkcError dash_pkc::ffi::PkcError::FromFFI(dash_pkc::ffi::capi::PkcError c_enum) {
    switch (c_enum) {
        case dash_pkc::ffi::capi::PkcError_InvalidKeyMaterial:
        case dash_pkc::ffi::capi::PkcError_InvalidSecretKey:
        case dash_pkc::ffi::capi::PkcError_InvalidPublicKey:
        case dash_pkc::ffi::capi::PkcError_InvalidSignature:
        case dash_pkc::ffi::capi::PkcError_VerifyFailed:
        case dash_pkc::ffi::capi::PkcError_InvalidMessageLength:
        case dash_pkc::ffi::capi::PkcError_EmptyAggregation:
        case dash_pkc::ffi::capi::PkcError_CountMismatch:
        case dash_pkc::ffi::capi::PkcError_ThresholdTooLarge:
        case dash_pkc::ffi::capi::PkcError_InsufficientShares:
        case dash_pkc::ffi::capi::PkcError_DuplicateShareId:
        case dash_pkc::ffi::capi::PkcError_InvalidShareId:
        case dash_pkc::ffi::capi::PkcError_InvalidVerificationVector:
        case dash_pkc::ffi::capi::PkcError_DuplicateMessage:
        case dash_pkc::ffi::capi::PkcError_ShareIdMismatch:
        case dash_pkc::ffi::capi::PkcError_InvalidPlaintextLength:
        case dash_pkc::ffi::capi::PkcError_DecryptionFailed:
        case dash_pkc::ffi::capi::PkcError_IndexOutOfRange:
        case dash_pkc::ffi::capi::PkcError_UnsupportedScheme:
        case dash_pkc::ffi::capi::PkcError_InvalidLength:
        case dash_pkc::ffi::capi::PkcError_InvalidEncoding:
        case dash_pkc::ffi::capi::PkcError_InsufficientEntropy:
        case dash_pkc::ffi::capi::PkcError_InternalError:
            return static_cast<dash_pkc::ffi::PkcError::Value>(c_enum);
        default:
            std::abort();
    }
}
#endif // dash_pkc_ffi_PkcError_HPP
