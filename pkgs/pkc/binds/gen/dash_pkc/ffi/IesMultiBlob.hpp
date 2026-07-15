#ifndef dash_pkc_ffi_IesMultiBlob_HPP
#define dash_pkc_ffi_IesMultiBlob_HPP

#include "IesMultiBlob.d.hpp"

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

    typedef struct IesMultiBlob_from_bytes_result {union {dash_pkc::ffi::capi::IesMultiBlob* ok; dash_pkc::ffi::capi::PkcError err;}; bool is_ok;} IesMultiBlob_from_bytes_result;
    IesMultiBlob_from_bytes_result IesMultiBlob_from_bytes(diplomat::capi::DiplomatU8View bytes);

    size_t IesMultiBlob_encoded_len(const dash_pkc::ffi::capi::IesMultiBlob* self);

    typedef struct IesMultiBlob_to_bytes_result {union { dash_pkc::ffi::capi::PkcError err;}; bool is_ok;} IesMultiBlob_to_bytes_result;
    IesMultiBlob_to_bytes_result IesMultiBlob_to_bytes(const dash_pkc::ffi::capi::IesMultiBlob* self, diplomat::capi::DiplomatU8ViewMut out);

    size_t IesMultiBlob_blob_count(const dash_pkc::ffi::capi::IesMultiBlob* self);

    typedef struct IesMultiBlob_data_len_at_result {union {size_t ok; dash_pkc::ffi::capi::PkcError err;}; bool is_ok;} IesMultiBlob_data_len_at_result;
    IesMultiBlob_data_len_at_result IesMultiBlob_data_len_at(const dash_pkc::ffi::capi::IesMultiBlob* self, size_t index);

    void IesMultiBlob_destroy(IesMultiBlob* self);

    } // extern "C"
} // namespace capi
} // namespace

inline diplomat::result<std::unique_ptr<dash_pkc::ffi::IesMultiBlob>, dash_pkc::ffi::PkcError> dash_pkc::ffi::IesMultiBlob::from_bytes(diplomat::span<const uint8_t> bytes) {
    auto result = dash_pkc::ffi::capi::IesMultiBlob_from_bytes({bytes.data(), bytes.size()});
    return result.is_ok ? diplomat::result<std::unique_ptr<dash_pkc::ffi::IesMultiBlob>, dash_pkc::ffi::PkcError>(diplomat::Ok<std::unique_ptr<dash_pkc::ffi::IesMultiBlob>>(std::unique_ptr<dash_pkc::ffi::IesMultiBlob>(dash_pkc::ffi::IesMultiBlob::FromFFI(result.ok)))) : diplomat::result<std::unique_ptr<dash_pkc::ffi::IesMultiBlob>, dash_pkc::ffi::PkcError>(diplomat::Err<dash_pkc::ffi::PkcError>(dash_pkc::ffi::PkcError::FromFFI(result.err)));
}

inline size_t dash_pkc::ffi::IesMultiBlob::encoded_len() const {
    auto result = dash_pkc::ffi::capi::IesMultiBlob_encoded_len(this->AsFFI());
    return result;
}

inline diplomat::result<std::monostate, dash_pkc::ffi::PkcError> dash_pkc::ffi::IesMultiBlob::to_bytes(diplomat::span<uint8_t> out) const {
    auto result = dash_pkc::ffi::capi::IesMultiBlob_to_bytes(this->AsFFI(),
        {out.data(), out.size()});
    return result.is_ok ? diplomat::result<std::monostate, dash_pkc::ffi::PkcError>(diplomat::Ok<std::monostate>()) : diplomat::result<std::monostate, dash_pkc::ffi::PkcError>(diplomat::Err<dash_pkc::ffi::PkcError>(dash_pkc::ffi::PkcError::FromFFI(result.err)));
}

inline size_t dash_pkc::ffi::IesMultiBlob::blob_count() const {
    auto result = dash_pkc::ffi::capi::IesMultiBlob_blob_count(this->AsFFI());
    return result;
}

inline diplomat::result<size_t, dash_pkc::ffi::PkcError> dash_pkc::ffi::IesMultiBlob::data_len_at(size_t index) const {
    auto result = dash_pkc::ffi::capi::IesMultiBlob_data_len_at(this->AsFFI(),
        index);
    return result.is_ok ? diplomat::result<size_t, dash_pkc::ffi::PkcError>(diplomat::Ok<size_t>(result.ok)) : diplomat::result<size_t, dash_pkc::ffi::PkcError>(diplomat::Err<dash_pkc::ffi::PkcError>(dash_pkc::ffi::PkcError::FromFFI(result.err)));
}

inline const dash_pkc::ffi::capi::IesMultiBlob* dash_pkc::ffi::IesMultiBlob::AsFFI() const {
    return reinterpret_cast<const dash_pkc::ffi::capi::IesMultiBlob*>(this);
}

inline dash_pkc::ffi::capi::IesMultiBlob* dash_pkc::ffi::IesMultiBlob::AsFFI() {
    return reinterpret_cast<dash_pkc::ffi::capi::IesMultiBlob*>(this);
}

inline const dash_pkc::ffi::IesMultiBlob* dash_pkc::ffi::IesMultiBlob::FromFFI(const dash_pkc::ffi::capi::IesMultiBlob* ptr) {
    return reinterpret_cast<const dash_pkc::ffi::IesMultiBlob*>(ptr);
}

inline dash_pkc::ffi::IesMultiBlob* dash_pkc::ffi::IesMultiBlob::FromFFI(dash_pkc::ffi::capi::IesMultiBlob* ptr) {
    return reinterpret_cast<dash_pkc::ffi::IesMultiBlob*>(ptr);
}

inline void dash_pkc::ffi::IesMultiBlob::operator delete(void* ptr) {
    dash_pkc::ffi::capi::IesMultiBlob_destroy(reinterpret_cast<dash_pkc::ffi::capi::IesMultiBlob*>(ptr));
}


#endif // dash_pkc_ffi_IesMultiBlob_HPP
