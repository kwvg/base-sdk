#ifndef dash_pkc_ffi_PublicKeyVec_D_HPP
#define dash_pkc_ffi_PublicKeyVec_D_HPP

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
namespace capi { struct PublicKey; }
class PublicKey;
namespace capi { struct PublicKeyVec; }
class PublicKeyVec;
} // namespace dash_pkc::ffi




namespace dash_pkc::ffi {
namespace capi {
    struct PublicKeyVec;
} // namespace capi
} // namespace

namespace dash_pkc::ffi {
/**
 * Builder collection of public keys for aggregate operations.
 */
class PublicKeyVec {
public:

  inline static std::unique_ptr<dash_pkc::ffi::PublicKeyVec> new_();

  inline void push(const dash_pkc::ffi::PublicKey& key);

  inline size_t len() const;

    inline const dash_pkc::ffi::capi::PublicKeyVec* AsFFI() const;
    inline dash_pkc::ffi::capi::PublicKeyVec* AsFFI();
    inline static const dash_pkc::ffi::PublicKeyVec* FromFFI(const dash_pkc::ffi::capi::PublicKeyVec* ptr);
    inline static dash_pkc::ffi::PublicKeyVec* FromFFI(dash_pkc::ffi::capi::PublicKeyVec* ptr);
    inline static void operator delete(void* ptr);
private:
    PublicKeyVec() = delete;
    PublicKeyVec(const dash_pkc::ffi::PublicKeyVec&) = delete;
    PublicKeyVec(dash_pkc::ffi::PublicKeyVec&&) noexcept = delete;
    PublicKeyVec operator=(const dash_pkc::ffi::PublicKeyVec&) = delete;
    PublicKeyVec operator=(dash_pkc::ffi::PublicKeyVec&&) noexcept = delete;
    static void operator delete[](void*, size_t) = delete;
};

} // namespace
#endif // dash_pkc_ffi_PublicKeyVec_D_HPP
