#ifndef dash_pkc_ffi_MessageVec_D_HPP
#define dash_pkc_ffi_MessageVec_D_HPP

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
namespace capi { struct MessageVec; }
class MessageVec;
} // namespace dash_pkc::ffi




namespace dash_pkc::ffi {
namespace capi {
    struct MessageVec;
} // namespace capi
} // namespace

namespace dash_pkc::ffi {
/**
 * Builder collection of arbitrary-length messages.
 */
class MessageVec {
public:

  inline static std::unique_ptr<dash_pkc::ffi::MessageVec> new_();

  inline void push(diplomat::span<const uint8_t> msg);

  inline size_t len() const;

    inline const dash_pkc::ffi::capi::MessageVec* AsFFI() const;
    inline dash_pkc::ffi::capi::MessageVec* AsFFI();
    inline static const dash_pkc::ffi::MessageVec* FromFFI(const dash_pkc::ffi::capi::MessageVec* ptr);
    inline static dash_pkc::ffi::MessageVec* FromFFI(dash_pkc::ffi::capi::MessageVec* ptr);
    inline static void operator delete(void* ptr);
private:
    MessageVec() = delete;
    MessageVec(const dash_pkc::ffi::MessageVec&) = delete;
    MessageVec(dash_pkc::ffi::MessageVec&&) noexcept = delete;
    MessageVec operator=(const dash_pkc::ffi::MessageVec&) = delete;
    MessageVec operator=(dash_pkc::ffi::MessageVec&&) noexcept = delete;
    static void operator delete[](void*, size_t) = delete;
};

} // namespace
#endif // dash_pkc_ffi_MessageVec_D_HPP
