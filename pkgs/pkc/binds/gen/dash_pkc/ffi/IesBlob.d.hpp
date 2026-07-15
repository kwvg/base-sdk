#ifndef dash_pkc_ffi_IesBlob_D_HPP
#define dash_pkc_ffi_IesBlob_D_HPP

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
namespace capi { struct IesBlob; }
class IesBlob;
class PkcError;
} // namespace dash_pkc::ffi




namespace dash_pkc::ffi {
namespace capi {
    struct IesBlob;
} // namespace capi
} // namespace

namespace dash_pkc::ffi {
/**
 * A single-recipient BLS-IES encrypted blob in Dash Core's
 * on-wire format.
 */
class IesBlob {
public:

  /**
   * Parse a consensus-encoded blob, rejecting trailing bytes.
   */
  inline static diplomat::result<std::unique_ptr<dash_pkc::ffi::IesBlob>, dash_pkc::ffi::PkcError> from_bytes(diplomat::span<const uint8_t> bytes);

  /**
   * Length of the consensus encoding in bytes.
   */
  inline size_t encoded_len() const;

  /**
   * Write the consensus encoding into `out` (exactly
   * `encoded_len()` bytes).
   */
  inline diplomat::result<std::monostate, dash_pkc::ffi::PkcError> to_bytes(diplomat::span<uint8_t> out) const;

  /**
   * Ciphertext (= plaintext) length in bytes.
   */
  inline size_t data_len() const;

    inline const dash_pkc::ffi::capi::IesBlob* AsFFI() const;
    inline dash_pkc::ffi::capi::IesBlob* AsFFI();
    inline static const dash_pkc::ffi::IesBlob* FromFFI(const dash_pkc::ffi::capi::IesBlob* ptr);
    inline static dash_pkc::ffi::IesBlob* FromFFI(dash_pkc::ffi::capi::IesBlob* ptr);
    inline static void operator delete(void* ptr);
private:
    IesBlob() = delete;
    IesBlob(const dash_pkc::ffi::IesBlob&) = delete;
    IesBlob(dash_pkc::ffi::IesBlob&&) noexcept = delete;
    IesBlob operator=(const dash_pkc::ffi::IesBlob&) = delete;
    IesBlob operator=(dash_pkc::ffi::IesBlob&&) noexcept = delete;
    static void operator delete[](void*, size_t) = delete;
};

} // namespace
#endif // dash_pkc_ffi_IesBlob_D_HPP
