#ifndef dash_pkc_ffi_IesBlob_HPP
#define dash_pkc_ffi_IesBlob_HPP

#include "IesBlob.d.hpp"

#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <memory>
#include <functional>
#include <optional>
#include <cstdlib>
#include "PkcError.hpp"
#include "../../diplomat_runtime.hpp"


namespace dash_pkc::ffi {
namespace capi {
    extern "C" {

    typedef struct IesBlob_from_bytes_result {union {dash_pkc::ffi::capi::IesBlob* ok; dash_pkc::ffi::capi::PkcError err;}; bool is_ok;} IesBlob_from_bytes_result;
    IesBlob_from_bytes_result IesBlob_from_bytes(diplomat::capi::DiplomatU8View bytes);

    size_t IesBlob_encoded_len(const dash_pkc::ffi::capi::IesBlob* self);

    typedef struct IesBlob_to_bytes_result {union { dash_pkc::ffi::capi::PkcError err;}; bool is_ok;} IesBlob_to_bytes_result;
    IesBlob_to_bytes_result IesBlob_to_bytes(const dash_pkc::ffi::capi::IesBlob* self, diplomat::capi::DiplomatU8ViewMut out);

    size_t IesBlob_data_len(const dash_pkc::ffi::capi::IesBlob* self);

    void IesBlob_destroy(IesBlob* self);

    } // extern "C"
} // namespace capi
} // namespace

inline diplomat::result<std::unique_ptr<dash_pkc::ffi::IesBlob>, dash_pkc::ffi::PkcError> dash_pkc::ffi::IesBlob::from_bytes(diplomat::span<const uint8_t> bytes) {
    auto result = dash_pkc::ffi::capi::IesBlob_from_bytes({bytes.data(), bytes.size()});
    return result.is_ok ? diplomat::result<std::unique_ptr<dash_pkc::ffi::IesBlob>, dash_pkc::ffi::PkcError>(diplomat::Ok<std::unique_ptr<dash_pkc::ffi::IesBlob>>(std::unique_ptr<dash_pkc::ffi::IesBlob>(dash_pkc::ffi::IesBlob::FromFFI(result.ok)))) : diplomat::result<std::unique_ptr<dash_pkc::ffi::IesBlob>, dash_pkc::ffi::PkcError>(diplomat::Err<dash_pkc::ffi::PkcError>(dash_pkc::ffi::PkcError::FromFFI(result.err)));
}

inline size_t dash_pkc::ffi::IesBlob::encoded_len() const {
    auto result = dash_pkc::ffi::capi::IesBlob_encoded_len(this->AsFFI());
    return result;
}

inline diplomat::result<std::monostate, dash_pkc::ffi::PkcError> dash_pkc::ffi::IesBlob::to_bytes(diplomat::span<uint8_t> out) const {
    auto result = dash_pkc::ffi::capi::IesBlob_to_bytes(this->AsFFI(),
        {out.data(), out.size()});
    return result.is_ok ? diplomat::result<std::monostate, dash_pkc::ffi::PkcError>(diplomat::Ok<std::monostate>()) : diplomat::result<std::monostate, dash_pkc::ffi::PkcError>(diplomat::Err<dash_pkc::ffi::PkcError>(dash_pkc::ffi::PkcError::FromFFI(result.err)));
}

inline size_t dash_pkc::ffi::IesBlob::data_len() const {
    auto result = dash_pkc::ffi::capi::IesBlob_data_len(this->AsFFI());
    return result;
}

inline const dash_pkc::ffi::capi::IesBlob* dash_pkc::ffi::IesBlob::AsFFI() const {
    return reinterpret_cast<const dash_pkc::ffi::capi::IesBlob*>(this);
}

inline dash_pkc::ffi::capi::IesBlob* dash_pkc::ffi::IesBlob::AsFFI() {
    return reinterpret_cast<dash_pkc::ffi::capi::IesBlob*>(this);
}

inline const dash_pkc::ffi::IesBlob* dash_pkc::ffi::IesBlob::FromFFI(const dash_pkc::ffi::capi::IesBlob* ptr) {
    return reinterpret_cast<const dash_pkc::ffi::IesBlob*>(ptr);
}

inline dash_pkc::ffi::IesBlob* dash_pkc::ffi::IesBlob::FromFFI(dash_pkc::ffi::capi::IesBlob* ptr) {
    return reinterpret_cast<dash_pkc::ffi::IesBlob*>(ptr);
}

inline void dash_pkc::ffi::IesBlob::operator delete(void* ptr) {
    dash_pkc::ffi::capi::IesBlob_destroy(reinterpret_cast<dash_pkc::ffi::capi::IesBlob*>(ptr));
}


#endif // dash_pkc_ffi_IesBlob_HPP
