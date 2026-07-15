#ifndef dash_pkc_ffi_PkcError_D_HPP
#define dash_pkc_ffi_PkcError_D_HPP

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
    enum PkcError {
      PkcError_InvalidKeyMaterial = 0,
      PkcError_InvalidSecretKey = 1,
      PkcError_InvalidPublicKey = 2,
      PkcError_InvalidSignature = 3,
      PkcError_VerifyFailed = 4,
      PkcError_InvalidMessageLength = 5,
      PkcError_EmptyAggregation = 6,
      PkcError_CountMismatch = 7,
      PkcError_ThresholdTooLarge = 8,
      PkcError_InsufficientShares = 9,
      PkcError_DuplicateShareId = 10,
      PkcError_InvalidShareId = 11,
      PkcError_InvalidVerificationVector = 12,
      PkcError_DuplicateMessage = 13,
      PkcError_ShareIdMismatch = 14,
      PkcError_InvalidPlaintextLength = 15,
      PkcError_DecryptionFailed = 16,
      PkcError_IndexOutOfRange = 17,
      PkcError_UnsupportedScheme = 18,
      PkcError_InvalidLength = 19,
      PkcError_InvalidEncoding = 20,
      PkcError_InsufficientEntropy = 21,
      PkcError_InternalError = 22,
    };

    typedef struct PkcError_option {union { PkcError ok; }; bool is_ok; } PkcError_option;
} // namespace capi
} // namespace

namespace dash_pkc::ffi {
/**
 * Error codes mirroring `dash_pkc::bls::BlsError`, plus FFI
 * buffer and encoding failures.
 */
class PkcError {
public:
    enum Value {
        InvalidKeyMaterial = 0,
        InvalidSecretKey = 1,
        InvalidPublicKey = 2,
        InvalidSignature = 3,
        VerifyFailed = 4,
        InvalidMessageLength = 5,
        EmptyAggregation = 6,
        CountMismatch = 7,
        ThresholdTooLarge = 8,
        InsufficientShares = 9,
        DuplicateShareId = 10,
        InvalidShareId = 11,
        InvalidVerificationVector = 12,
        DuplicateMessage = 13,
        ShareIdMismatch = 14,
        InvalidPlaintextLength = 15,
        DecryptionFailed = 16,
        IndexOutOfRange = 17,
        UnsupportedScheme = 18,
        InvalidLength = 19,
        InvalidEncoding = 20,
        InsufficientEntropy = 21,
        InternalError = 22,
    };

    PkcError(): value(Value::InvalidKeyMaterial) {}

    // Implicit conversions between enum and ::Value
    constexpr PkcError(Value v) : value(v) {}
    constexpr operator Value() const { return value; }
    // Prevent usage as boolean value
    explicit operator bool() const = delete;

    inline dash_pkc::ffi::capi::PkcError AsFFI() const;
    inline static dash_pkc::ffi::PkcError FromFFI(dash_pkc::ffi::capi::PkcError c_enum);
private:
    Value value;
};

} // namespace
#endif // dash_pkc_ffi_PkcError_D_HPP
