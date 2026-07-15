#ifndef dash_pkc_ffi_IesMultiBlob_D_HPP
#define dash_pkc_ffi_IesMultiBlob_D_HPP

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
namespace capi { struct IesMultiBlob; }
class IesMultiBlob;
class PkcError;
} // namespace dash_pkc::ffi




namespace dash_pkc::ffi {
namespace capi {
    struct IesMultiBlob;
} // namespace capi
} // namespace

namespace dash_pkc::ffi {
/**
 * A multi-recipient BLS-IES encrypted blob in Dash Core's
 * on-wire format.
 */
class IesMultiBlob {
public:

  /**
   * Parse a consensus-encoded blob, rejecting trailing bytes.
   */
  inline static diplomat::result<std::unique_ptr<dash_pkc::ffi::IesMultiBlob>, dash_pkc::ffi::PkcError> from_bytes(diplomat::span<const uint8_t> bytes);

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
   * Number of recipient slots.
   */
  inline size_t blob_count() const;

  /**
   * Ciphertext (= plaintext) length of one recipient slot.
   */
  inline diplomat::result<size_t, dash_pkc::ffi::PkcError> data_len_at(size_t index) const;

    inline const dash_pkc::ffi::capi::IesMultiBlob* AsFFI() const;
    inline dash_pkc::ffi::capi::IesMultiBlob* AsFFI();
    inline static const dash_pkc::ffi::IesMultiBlob* FromFFI(const dash_pkc::ffi::capi::IesMultiBlob* ptr);
    inline static dash_pkc::ffi::IesMultiBlob* FromFFI(dash_pkc::ffi::capi::IesMultiBlob* ptr);
    inline static void operator delete(void* ptr);
private:
    IesMultiBlob() = delete;
    IesMultiBlob(const dash_pkc::ffi::IesMultiBlob&) = delete;
    IesMultiBlob(dash_pkc::ffi::IesMultiBlob&&) noexcept = delete;
    IesMultiBlob operator=(const dash_pkc::ffi::IesMultiBlob&) = delete;
    IesMultiBlob operator=(dash_pkc::ffi::IesMultiBlob&&) noexcept = delete;
    static void operator delete[](void*, size_t) = delete;
};

} // namespace
#endif // dash_pkc_ffi_IesMultiBlob_D_HPP
