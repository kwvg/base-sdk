#ifndef dash_pkc_ffi_SignatureVec_D_HPP
#define dash_pkc_ffi_SignatureVec_D_HPP

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
namespace capi { struct Signature; }
class Signature;
namespace capi { struct SignatureVec; }
class SignatureVec;
} // namespace dash_pkc::ffi




namespace dash_pkc::ffi {
namespace capi {
    struct SignatureVec;
} // namespace capi
} // namespace

namespace dash_pkc::ffi {
/**
 * Builder collection of signatures for aggregate operations.
 */
class SignatureVec {
public:

  inline static std::unique_ptr<dash_pkc::ffi::SignatureVec> new_();

  inline void push(const dash_pkc::ffi::Signature& sig);

  inline size_t len() const;

    inline const dash_pkc::ffi::capi::SignatureVec* AsFFI() const;
    inline dash_pkc::ffi::capi::SignatureVec* AsFFI();
    inline static const dash_pkc::ffi::SignatureVec* FromFFI(const dash_pkc::ffi::capi::SignatureVec* ptr);
    inline static dash_pkc::ffi::SignatureVec* FromFFI(dash_pkc::ffi::capi::SignatureVec* ptr);
    inline static void operator delete(void* ptr);
private:
    SignatureVec() = delete;
    SignatureVec(const dash_pkc::ffi::SignatureVec&) = delete;
    SignatureVec(dash_pkc::ffi::SignatureVec&&) noexcept = delete;
    SignatureVec operator=(const dash_pkc::ffi::SignatureVec&) = delete;
    SignatureVec operator=(dash_pkc::ffi::SignatureVec&&) noexcept = delete;
    static void operator delete[](void*, size_t) = delete;
};

} // namespace
#endif // dash_pkc_ffi_SignatureVec_D_HPP
