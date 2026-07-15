#ifndef dash_pkc_ffi_IdVec_D_HPP
#define dash_pkc_ffi_IdVec_D_HPP

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
namespace capi { struct IdVec; }
class IdVec;
class PkcError;
} // namespace dash_pkc::ffi




namespace dash_pkc::ffi {
namespace capi {
    struct IdVec;
} // namespace capi
} // namespace

namespace dash_pkc::ffi {
/**
 * Builder collection of 32-byte participant ids.
 */
class IdVec {
public:

  inline static std::unique_ptr<dash_pkc::ffi::IdVec> new_();

  /**
   * Append a 32-byte participant id.
   */
  inline diplomat::result<std::monostate, dash_pkc::ffi::PkcError> push(diplomat::span<const uint8_t> id);

  inline size_t len() const;

    inline const dash_pkc::ffi::capi::IdVec* AsFFI() const;
    inline dash_pkc::ffi::capi::IdVec* AsFFI();
    inline static const dash_pkc::ffi::IdVec* FromFFI(const dash_pkc::ffi::capi::IdVec* ptr);
    inline static dash_pkc::ffi::IdVec* FromFFI(dash_pkc::ffi::capi::IdVec* ptr);
    inline static void operator delete(void* ptr);
private:
    IdVec() = delete;
    IdVec(const dash_pkc::ffi::IdVec&) = delete;
    IdVec(dash_pkc::ffi::IdVec&&) noexcept = delete;
    IdVec operator=(const dash_pkc::ffi::IdVec&) = delete;
    IdVec operator=(dash_pkc::ffi::IdVec&&) noexcept = delete;
    static void operator delete[](void*, size_t) = delete;
};

} // namespace
#endif // dash_pkc_ffi_IdVec_D_HPP
