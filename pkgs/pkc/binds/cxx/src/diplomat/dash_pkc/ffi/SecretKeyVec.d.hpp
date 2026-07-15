#ifndef dash_pkc_ffi_SecretKeyVec_D_HPP
#define dash_pkc_ffi_SecretKeyVec_D_HPP

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
namespace capi { struct SecretKey; }
class SecretKey;
namespace capi { struct SecretKeyVec; }
class SecretKeyVec;
} // namespace dash_pkc::ffi




namespace dash_pkc::ffi {
namespace capi {
    struct SecretKeyVec;
} // namespace capi
} // namespace

namespace dash_pkc::ffi {
/**
 * Builder collection of secret keys for aggregate operations.
 */
class SecretKeyVec {
public:

  inline static std::unique_ptr<dash_pkc::ffi::SecretKeyVec> new_();

  inline void push(const dash_pkc::ffi::SecretKey& key);

  inline size_t len() const;

    inline const dash_pkc::ffi::capi::SecretKeyVec* AsFFI() const;
    inline dash_pkc::ffi::capi::SecretKeyVec* AsFFI();
    inline static const dash_pkc::ffi::SecretKeyVec* FromFFI(const dash_pkc::ffi::capi::SecretKeyVec* ptr);
    inline static dash_pkc::ffi::SecretKeyVec* FromFFI(dash_pkc::ffi::capi::SecretKeyVec* ptr);
    inline static void operator delete(void* ptr);
private:
    SecretKeyVec() = delete;
    SecretKeyVec(const dash_pkc::ffi::SecretKeyVec&) = delete;
    SecretKeyVec(dash_pkc::ffi::SecretKeyVec&&) noexcept = delete;
    SecretKeyVec operator=(const dash_pkc::ffi::SecretKeyVec&) = delete;
    SecretKeyVec operator=(dash_pkc::ffi::SecretKeyVec&&) noexcept = delete;
    static void operator delete[](void*, size_t) = delete;
};

} // namespace
#endif // dash_pkc_ffi_SecretKeyVec_D_HPP
